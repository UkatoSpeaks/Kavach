/** Client-side checks for QR images, matching the API's limits (PNG or JPEG, max 5 MB). */

export const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
export const IMAGE_TYPES = ["image/png", "image/jpeg"];

/** Longest side for a shrunk photo: plenty for a QR code, well under 5 MB as JPEG. */
const MAX_SIDE = 2000;

export type ImageCheck = { ok: true; file: File } | { ok: false; message: string };

/**
 * Accept PNG/JPEG up to 5 MB. Bigger photos (straight from a phone camera) are scaled down
 * in the browser rather than rejected; if that fails, they are rejected.
 */
export async function prepareImage(file: File): Promise<ImageCheck> {
  if (!IMAGE_TYPES.includes(file.type)) {
    return { ok: false, message: "Please choose a PNG or JPG image." };
  }
  if (file.size <= MAX_IMAGE_BYTES) return { ok: true, file };

  const shrunk = await shrink(file).catch(() => null);
  if (shrunk && shrunk.size <= MAX_IMAGE_BYTES) return { ok: true, file: shrunk };
  return {
    ok: false,
    message: "That image is over 5 MB. Try a screenshot, or crop the photo to the QR code.",
  };
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
