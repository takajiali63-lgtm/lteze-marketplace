/**
 * WhatsApp order message ("customer order" sent to the seller).
 * Price always comes from the database; the total is computed here in integer cents.
 * No shipping, discounts, taxes, fees or payment method are ever added.
 */
export const MAX_ORDER_QTY = 999;

/** Missing qty → 1 (old links keep working). Anything else must be an integer 1..999, or null (rejected). */
export function parseQty(raw: unknown): number | null {
  if (raw === undefined || raw === "") return 1;
  if (typeof raw !== "string" || !/^\d{1,4}$/.test(raw)) return null;
  const n = Number(raw);
  return n >= 1 && n <= MAX_ORDER_QTY ? n : null;
}

/** "25", "25.5", "25.00" → cents, without floating point. */
export function toCents(price: string | number): number {
  const s = String(price).trim();
  const m = /^(\d+)(?:\.(\d{1,2}))?$/.exec(s);
  if (!m) throw new Error(`invalid price: ${s}`);
  return Number(m[1]) * 100 + Number((m[2] ?? "").padEnd(2, "0"));
}

export function formatUsd(cents: number): string {
  return `$${Math.floor(cents / 100)}.${String(cents % 100).padStart(2, "0")}`;
}

export function buildOrderMessage(o: { name: string; price: string | number; qty: number; link: string }): string {
  const unit = toCents(o.price);
  return [
    "🛍️ طلب جديد من LTEZE",
    "",
    "👋 مرحباً! أريد طلب المنتج التالي:",
    "",
    "📦 تفاصيل الطلب",
    "",
    `🛒 المنتج: ${o.name}`,
    `🔢 الكمية: ${o.qty}`,
    `💵 سعر القطعة: ${formatUsd(unit)}`,
    `💰 المجموع: ${formatUsd(unit * o.qty)}`,
    "",
    `🔗 رابط المنتج: ${o.link}`,
    "",
    "🙏 شكراً، بانتظار تأكيد الطلب والتفاصيل.",
    "✨ من LTEZE",
  ].join("\n");
}
