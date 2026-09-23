import sharp, { type Metadata } from "sharp";

// ============================================================ limits

export const MAX_IMAGES_PER_PRODUCT = 10;
export const MAX_UPLOAD_BYTES = Number(process.env.MAX_IMAGE_BYTES ?? 5 * 1024 * 1024); // 5 MB per file
export const MIN_IMAGE_SIDE = 200; // px — keeps images clear on phones
export const MAX_OUTPUT_SIDE = 2000; // px — longest side after resize
export const MAX_INPUT_PIXELS = 40_000_000; // decompression-bomb guard
export const ALLOWED_UPLOAD_MIME = ["image/jpeg", "image/png", "image/webp"] as const;
export type AllowedMime = (typeof ALLOWED_UPLOAD_MIME)[number];

export class ImageRejected extends Error {
  constructor(message: string) {
    super(message);
  }
}

export class GalleryError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

// ============================================================ validation

/** Detects the real file type from magic bytes. The client-sent MIME type is never trusted. */
export function sniffImageType(buf: Buffer): AllowedMime | null {
  if (buf.length < 12) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "image/jpeg";
  if (
    buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47 &&
    buf[4] === 0x0d && buf[5] === 0x0a && buf[6] === 0x1a && buf[7] === 0x0a
  ) {
    return "image/png";
  }
  if (buf.toString("ascii", 0, 4) === "RIFF" && buf.toString("ascii", 8, 12) === "WEBP") return "image/webp";
  return null;
}

export interface ProcessedImage {
  buffer: Buffer;
  mime: "image/webp";
  width: number;
  height: number;
  bytes: number;
}

const FORMAT_FOR_MIME: Record<AllowedMime, string> = {
  "image/jpeg": "jpeg",
  "image/png": "png",
  "image/webp": "webp",
};

/**
 * Validates and re-encodes an uploaded image:
 * - real type must be JPEG/PNG/WebP (magic bytes + full decode)
 * - size and pixel limits enforced
 * - auto-rotated, resized to max 2000px, re-encoded as WebP
 * - ALL metadata (EXIF, GPS location, ICC scripts, etc.) is stripped
 * Re-encoding also neutralises polyglot/malicious payloads hidden in the original file.
 */
export async function processImage(input: Buffer): Promise<ProcessedImage> {
  if (input.length === 0) throw new ImageRejected("الملف فارغ");
  if (input.length > MAX_UPLOAD_BYTES) {
    throw new ImageRejected(`حجم الصورة يتجاوز ${Math.round(MAX_UPLOAD_BYTES / 1024 / 1024)}MB`);
  }
  const sniffed = sniffImageType(input);
  if (!sniffed) throw new ImageRejected("نوع الملف غير مسموح. المسموح: JPG, PNG, WebP");

  let meta: Metadata;
  try {
    meta = await sharp(input, { failOn: "error", limitInputPixels: MAX_INPUT_PIXELS }).metadata();
  } catch {
    throw new ImageRejected("الملف ليس صورة صالحة أو تالف");
  }
  if (meta.format !== FORMAT_FOR_MIME[sniffed]) throw new ImageRejected("محتوى الملف لا يطابق نوعه");
  if ((meta.pages ?? 1) > 1) throw new ImageRejected("الصور المتحركة غير مسموحة");
  const w = meta.autoOrient?.width ?? meta.width ?? 0;
  const h = meta.autoOrient?.height ?? meta.height ?? 0;
  if (w < MIN_IMAGE_SIDE || h < MIN_IMAGE_SIDE) {
    throw new ImageRejected(`الصورة صغيرة جداً. الحد الأدنى ${MIN_IMAGE_SIDE}×${MIN_IMAGE_SIDE} بكسل`);
  }

  try {
    const { data, info } = await sharp(input, { failOn: "error", limitInputPixels: MAX_INPUT_PIXELS })
      .rotate() // apply EXIF orientation, then metadata is dropped
      .resize({ width: MAX_OUTPUT_SIDE, height: MAX_OUTPUT_SIDE, fit: "inside", withoutEnlargement: true })
      .webp({ quality: 82 })
      .toBuffer({ resolveWithObject: true });
    return { buffer: data, mime: "image/webp", width: info.width, height: info.height, bytes: data.length };
  } catch {
    throw new ImageRejected("تعذّرت معالجة الصورة");
  }
}

// ============================================================ gallery rules (pure)

export interface GalleryItem {
  id: string;
  position: number;
  is_primary: boolean;
}

/** Positions become 0..n-1 (stable), and exactly one primary exists when there are images. */
export function normalizeGallery(items: readonly GalleryItem[]): GalleryItem[] {
  const sorted = [...items].sort((a, b) => a.position - b.position);
  const primaryId = sorted.find((i) => i.is_primary)?.id ?? sorted[0]?.id;
  return sorted.map((i, idx) => ({ id: i.id, position: idx, is_primary: i.id === primaryId }));
}

export function appendToGallery(items: readonly GalleryItem[], newIds: readonly string[]): GalleryItem[] {
  const base = normalizeGallery(items);
  if (base.length + newIds.length > MAX_IMAGES_PER_PRODUCT) {
    throw new GalleryError(
      409,
      "too_many_images",
      `الحد الأقصى ${MAX_IMAGES_PER_PRODUCT} صور للمنتج. المتبقي: ${Math.max(0, MAX_IMAGES_PER_PRODUCT - base.length)}`,
    );
  }
  const added = newIds.map((id, k) => ({ id, position: base.length + k, is_primary: false }));
  return normalizeGallery([...base, ...added]);
}

export function reorderGallery(items: readonly GalleryItem[], orderedIds: readonly string[]): GalleryItem[] {
  const base = normalizeGallery(items);
  const known = new Set(base.map((i) => i.id));
  const given = new Set(orderedIds);
  if (orderedIds.length !== base.length || given.size !== orderedIds.length || ![...given].every((id) => known.has(id))) {
    throw new GalleryError(400, "invalid_order", "يجب إرسال كل معرّفات صور المنتج مرة واحدة بالترتيب الجديد");
  }
  const primaryId = base.find((i) => i.is_primary)?.id;
  return orderedIds.map((id, idx) => ({ id, position: idx, is_primary: id === primaryId }));
}

export function setPrimaryInGallery(items: readonly GalleryItem[], id: string): GalleryItem[] {
  const base = normalizeGallery(items);
  if (!base.some((i) => i.id === id)) throw new GalleryError(404, "image_not_found", "الصورة غير موجودة");
  return base.map((i) => ({ ...i, is_primary: i.id === id }));
}

/** Removing the primary promotes the first remaining image in gallery order. */
export function removeFromGallery(items: readonly GalleryItem[], id: string): GalleryItem[] {
  const base = normalizeGallery(items);
  if (!base.some((i) => i.id === id)) throw new GalleryError(404, "image_not_found", "الصورة غير موجودة");
  return normalizeGallery(base.filter((i) => i.id !== id).map((i) => ({ ...i, is_primary: i.is_primary })));
}
