"use client";

import {
  useEffect,
  useEffectEvent,
  useId,
  useRef,
  useState,
  useSyncExternalStore,
  type DragEvent,
  type ReactNode,
} from "react";
import { Camera, ClipboardPaste, ImageUp, X } from "lucide-react";
import { IMAGE_RULES, prepareImage, type ImageKind } from "@/lib/image";
import { cn } from "@/lib/cn";

type ImageFieldProps = {
  kind: ImageKind;
  /** The field's visible label. */
  label: string;
  /** Alt text for the preview of the chosen image. */
  previewAlt: string;
  file: File | null;
  previewUrl: string | null;
  onChange: (file: File | null) => void;
  disabled?: boolean;
  /**
   * Accept images pasted anywhere on the page (Ctrl/⌘+V) while this field is shown, and show
   * a Paste button where the browser can read images from the clipboard.
   */
  pasteable?: boolean;
  /** Shown under the uploader, e.g. a privacy note. */
  note?: ReactNode;
  previewClassName?: string;
};

const noop = () => () => {};

/** Reading images from the clipboard needs a secure context and a recent browser. */
function useCanReadClipboard(): boolean {
  return useSyncExternalStore(
    noop,
    () => typeof navigator.clipboard?.read === "function",
    () => false,
  );
}

function imageFrom(data: DataTransfer | null): File | null {
  for (const item of data?.items ?? []) {
    if (item.kind === "file" && item.type.startsWith("image/")) return item.getAsFile();
  }
  return null;
}

function named(file: Blob, base: string): File {
  const ext = file.type.split("/")[1]?.replace("jpeg", "jpg") ?? "png";
  return new File([file], `${base}.${ext}`, { type: file.type });
}

const buttonClass =
  "inline-flex min-h-12 items-center justify-center gap-2 rounded-xl border-2 border-ink bg-card px-4 font-bold shadow-brutal-sm hover:bg-accent-tint active:translate-y-0.5 active:shadow-none disabled:opacity-50";

/**
 * Drag-and-drop or tap to upload an image, take a photo on a phone, or (with `pasteable`)
 * paste one from the clipboard. Images are checked and, if too big, shrunk in the browser.
 */
export function ImageField({
  kind,
  label,
  previewAlt,
  file,
  previewUrl,
  onChange,
  disabled,
  pasteable = false,
  note,
  previewClassName = "size-28",
}: ImageFieldProps) {
  const id = useId();
  const uploadRef = useRef<HTMLInputElement>(null);
  const cameraRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const canReadClipboard = useCanReadClipboard();

  async function accept(picked: File | null | undefined, how?: "pasted") {
    if (!picked) return;
    setError(null);
    setStatus(null);
    setWorking(true);
    const checked = await prepareImage(picked, kind);
    setWorking(false);
    if (checked.ok) {
      onChange(checked.file);
      if (how === "pasted") setStatus("Screenshot pasted from your clipboard.");
    } else {
      setError(checked.message);
    }
  }

  // Ctrl/⌘+V anywhere on the page. Text pasted into a text field is left alone.
  const onPaste = useEffectEvent((e: ClipboardEvent) => {
    if (disabled || working) return;
    const image = imageFrom(e.clipboardData);
    if (image) {
      e.preventDefault();
      void accept(named(image, "pasted-screenshot"), "pasted");
      return;
    }
    const target = e.target as HTMLElement | null;
    if (target?.closest("input, textarea, [contenteditable='true']")) return;
    if (e.clipboardData?.types.includes("text/plain")) {
      setStatus(null);
      setError("That's text, not an image. To check text, use the Message tab.");
    }
  });

  useEffect(() => {
    if (!pasteable) return;
    const listener = (e: ClipboardEvent) => onPaste(e);
    window.addEventListener("paste", listener);
    return () => window.removeEventListener("paste", listener);
  }, [pasteable]);

  async function pasteFromButton() {
    setError(null);
    setStatus(null);
    try {
      for (const item of await navigator.clipboard.read()) {
        const type = item.types.find((t) => t.startsWith("image/"));
        if (type) {
          await accept(named(await item.getType(type), "pasted-screenshot"), "pasted");
          return;
        }
      }
      setError("There's no image on your clipboard. Take a screenshot, copy it, then paste.");
    } catch {
      setError("Couldn't read the clipboard. Choose the image instead.");
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    if (!disabled) void accept(e.dataTransfer.files[0]);
  }

  function pick(input: HTMLInputElement) {
    void accept(input.files?.[0]);
    input.value = "";
  }

  return (
    <div>
      <p id={`${id}-label`} className="font-bold">
        {label}
      </p>

      {file && previewUrl ? (
        <div className="mt-2 flex items-center gap-4 rounded-xl border-2 border-ink bg-card p-3">
          {/* eslint-disable-next-line @next/next/no-img-element -- local blob: preview */}
          <img
            src={previewUrl}
            alt={previewAlt}
            className={cn(
              "shrink-0 rounded-lg border-2 border-ink bg-paper object-contain",
              previewClassName,
            )}
          />
          <div className="min-w-0 flex-1">
            <p className="truncate font-semibold">{file.name}</p>
            <p className="text-sm text-ink-muted">{(file.size / 1024).toFixed(0)} KB</p>
            <button
              type="button"
              onClick={() => {
                onChange(null);
                setError(null);
                setStatus(null);
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
          role="group"
          aria-labelledby={`${id}-label`}
          aria-describedby={`${id}-rules`}
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
            <span className="hidden sm:inline">
              Drag an image here{pasteable ? ", paste it, " : ""} or choose one.
            </span>
            <span className="sm:hidden">Choose an image from your phone.</span>
          </p>
          <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
            <button
              type="button"
              onClick={() => uploadRef.current?.click()}
              disabled={disabled || working}
              className={buttonClass}
            >
              <ImageUp aria-hidden className="size-5" />
              {working ? "Preparing…" : "Choose image"}
            </button>
            {pasteable && canReadClipboard && (
              <button
                type="button"
                onClick={pasteFromButton}
                disabled={disabled || working}
                className={buttonClass}
              >
                <ClipboardPaste aria-hidden className="size-5" />
                Paste
              </button>
            )}
            <button
              type="button"
              onClick={() => cameraRef.current?.click()}
              disabled={disabled || working}
              className={cn(buttonClass, "sm:hidden")}
            >
              <Camera aria-hidden className="size-5" />
              Take a photo
            </button>
          </div>
          <p id={`${id}-rules`} className="text-sm text-ink-muted">
            {IMAGE_RULES[kind]}
            {pasteable && (
              <span className="hidden sm:inline">
                {" "}
                Or press{" "}
                <kbd className="rounded border-2 border-ink/40 px-1 font-mono text-xs">Ctrl</kbd>/
                <kbd className="rounded border-2 border-ink/40 px-1 font-mono text-xs">⌘</kbd>
                {" + "}
                <kbd className="rounded border-2 border-ink/40 px-1 font-mono text-xs">V</kbd> to
                paste.
              </span>
            )}
          </p>
        </div>
      )}

      <input
        ref={uploadRef}
        type="file"
        accept={kind === "qr" ? "image/png,image/jpeg" : "image/png,image/jpeg,image/webp"}
        className="sr-only"
        tabIndex={-1}
        aria-hidden
        onChange={(e) => pick(e.target)}
      />
      <input
        ref={cameraRef}
        type="file"
        accept="image/*"
        capture="environment"
        className="sr-only"
        tabIndex={-1}
        aria-hidden
        onChange={(e) => pick(e.target)}
      />

      {note}

      <p
        aria-live="polite"
        className={cn(
          "mt-1.5 text-sm font-semibold",
          error ? "text-accent-dark" : "text-ink-muted",
        )}
      >
        {error ?? status}
      </p>
    </div>
  );
}
