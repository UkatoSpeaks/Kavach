"use client";

import { useId, useRef, useState, type DragEvent } from "react";
import { Camera, ImageUp, X } from "lucide-react";
import { prepareImage } from "@/lib/image";
import { cn } from "@/lib/cn";

type QrFieldProps = {
  file: File | null;
  previewUrl: string | null;
  onChange: (file: File | null) => void;
  disabled?: boolean;
};

/** Drag-and-drop or tap to upload a QR image, or take a photo on a phone. */
export function QrField({ file, previewUrl, onChange, disabled }: QrFieldProps) {
  const id = useId();
  const uploadRef = useRef<HTMLInputElement>(null);
  const cameraRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [working, setWorking] = useState(false);

  async function accept(picked: File | undefined) {
    if (!picked) return;
    setError(null);
    setWorking(true);
    const checked = await prepareImage(picked);
    setWorking(false);
    if (checked.ok) onChange(checked.file);
    else setError(checked.message);
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    if (!disabled) void accept(e.dataTransfer.files[0]);
  }

  return (
    <div>
      <p id={`${id}-label`} className="font-bold">
        Upload a photo or screenshot of the QR code
      </p>

      {file && previewUrl ? (
        <div className="mt-2 flex items-center gap-4 rounded-xl border-2 border-ink bg-card p-3">
          {/* eslint-disable-next-line @next/next/no-img-element -- local blob: preview */}
          <img
            src={previewUrl}
            alt="Preview of the chosen QR code image"
            className="size-28 shrink-0 rounded-lg border-2 border-ink bg-paper object-contain"
          />
          <div className="min-w-0 flex-1">
            <p className="truncate font-semibold">{file.name}</p>
            <p className="text-sm text-ink-muted">{(file.size / 1024).toFixed(0)} KB</p>
            <button
              type="button"
              onClick={() => {
                onChange(null);
                setError(null);
              }}
              disabled={disabled}
              className="mt-2 inline-flex min-h-10 items-center gap-1.5 rounded-lg border-2 border-ink bg-paper px-3 text-sm font-bold hover:bg-accent-tint disabled:opacity-50"
            >
              <X aria-hidden className="size-4" />
              Remove
            </button>
          </div>
        </div>
      ) : (
        <div
          onDragOver={(e) => {
            e.preventDefault();
            if (!disabled) setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={cn(
            "mt-2 flex flex-col items-center gap-3 rounded-xl border-2 border-dashed border-ink px-4 py-8 text-center transition-colors",
            dragging ? "bg-accent-tint" : "bg-card",
          )}
        >
          <ImageUp aria-hidden className="size-9 text-accent" />
          <p className="text-ink-muted">
            <span className="hidden sm:inline">Drag an image here, or </span>
            <span className="sm:hidden">Choose an image from your phone.</span>
          </p>
          <div className="flex flex-col gap-2 sm:flex-row">
            <button
              type="button"
              onClick={() => uploadRef.current?.click()}
              disabled={disabled || working}
              aria-describedby={`${id}-rules`}
              className="inline-flex min-h-12 items-center justify-center gap-2 rounded-xl border-2 border-ink bg-card px-4 font-bold shadow-brutal-sm hover:bg-accent-tint active:translate-y-0.5 active:shadow-none disabled:opacity-50"
            >
              <ImageUp aria-hidden className="size-5" />
              {working ? "Preparing…" : "Choose image"}
            </button>
            <button
              type="button"
              onClick={() => cameraRef.current?.click()}
              disabled={disabled || working}
              className="inline-flex min-h-12 items-center justify-center gap-2 rounded-xl border-2 border-ink bg-card px-4 font-bold shadow-brutal-sm hover:bg-accent-tint active:translate-y-0.5 active:shadow-none disabled:opacity-50 sm:hidden"
            >
              <Camera aria-hidden className="size-5" />
              Take a photo
            </button>
          </div>
          <p id={`${id}-rules`} className="text-sm text-ink-muted">
            PNG or JPG, up to 5 MB.
          </p>
        </div>
      )}

      <input
        ref={uploadRef}
        type="file"
        accept="image/png,image/jpeg"
        className="sr-only"
        tabIndex={-1}
        aria-hidden
        onChange={(e) => {
          void accept(e.target.files?.[0]);
          e.target.value = "";
        }}
      />
      <input
        ref={cameraRef}
        type="file"
        accept="image/*"
        capture="environment"
        className="sr-only"
        tabIndex={-1}
        aria-hidden
        onChange={(e) => {
          void accept(e.target.files?.[0]);
          e.target.value = "";
        }}
      />

      <p aria-live="polite" className="mt-1.5 text-sm font-semibold text-accent-dark">
        {error}
      </p>
    </div>
  );
}
