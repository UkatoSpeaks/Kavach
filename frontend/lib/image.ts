/** Client-side checks for uploaded images, matching the API's limits (max 5 MB). */

export const MAX_IMAGE_BYTES = 5 * 1024 * 1024;

export type ImageKind = "qr" | "screenshot";

/** What each endpoint accepts: /analyze/qr PNG or JPEG, /analyze/screenshot also WEBP. */
export const IMAGE_TYPES: Record<ImageKind, string[]> = {
  qr: ["image/png", "image/jpeg"],
  screenshot: ["image/png", "image/jpeg", "image/webp"],
};

export const IMAGE_RULES: Record<ImageKind, string> = {
  qr: "PNG or JPG, up to 5 MB.",
  screenshot: "PNG, JPG or WEBP, up to 5 MB.",
};

const TYPE_MESSAGE: Record<ImageKind, string> = {
  qr: "Please choose a PNG or JPG image.",
  screenshot: "Please choose a PNG, JPG or WEBP image.",
};

const TOO_BIG_MESSAGE: Record<ImageKind, string> = {
  qr: "That image is over 5 MB. Try a screenshot, or crop the photo to the QR code.",
  screenshot: "That image is over 5 MB. Try a normal phone screenshot, or crop it to the message.",
};

/**
 * Longest side for a shrunk image: plenty for a QR code or for reading text (the API reads
 * screenshots at 1600 px), and well under 5 MB as JPEG.
 */
const MAX_SIDE = 2000;

export type ImageCheck = { ok: true; file: File } | { ok: false; message: string };

/**
 * Accept the endpoint's image types up to 5 MB. Bigger images (straight from a phone camera)
 * are scaled down in the browser rather than rejected; if that fails, they are rejected.
 */
export async function prepareImage(file: File, kind: ImageKind = "qr"): Promise<ImageCheck> {
  if (!IMAGE_TYPES[kind].includes(file.type)) {
    return { ok: false, message: TYPE_MESSAGE[kind] };
  }
  if (file.size <= MAX_IMAGE_BYTES) return { ok: true, file };

  const shrunk = await shrink(file).catch(() => null);
  if (shrunk && shrunk.size <= MAX_IMAGE_BYTES) return { ok: true, file: shrunk };
  return { ok: false, message: TOO_BIG_MESSAGE[kind] };
}

async function shrink(file: File): Promise<File | null> {
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(1, MAX_SIDE / Math.max(bitmap.width, bitmap.height));
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(bitmap.width * scale);
  canvas.height = Math.round(bitmap.height * scale);
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close();
  const blob = await new Promise<Blob | null>((r) => canvas.toBlob(r, "image/jpeg", 0.9));
  if (!blob) return null;
  return new File([blob], file.name.replace(/\.\w+$/, "") + ".jpg", { type: "image/jpeg" });
}
