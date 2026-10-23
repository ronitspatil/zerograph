"use client";
import { useId, useState } from "react";
import { Upload } from "lucide-react";

/**
 * A file field in the console's control style: a fixed-height control holding a
 * "Choose file" button and the chosen file name, with a hint below. The native input
 * stays in the control (visually hidden, focusable), so the label, keyboard and
 * screen readers work as usual; picking a file never changes the field's size.
 */
export function FilePicker({
  label,
  hint,
  accept,
  multiple = false,
  disabled = false,
  onFiles,
}: {
  label: string;
  hint?: string;
  accept?: string;
  multiple?: boolean;
  disabled?: boolean;
  onFiles: (files: File[]) => void;
}) {
  const id = useId();
  const [names, setNames] = useState<string[]>([]);
  const chosen =
    names.length === 0
      ? multiple
        ? "No files chosen"
        : "No file chosen"
      : names.length === 1
        ? names[0]
        : `${names.length} files · ${names.join(", ")}`;
  return (
    <label className="file-field">
      <span id={`${id}-label`}>{label}</span>
      <span
        className={disabled ? "file-picker disabled" : "file-picker"}
        title={names.length ? names.join(", ") : undefined}
      >
        <input
          type="file"
          className="file-picker-input"
          accept={accept}
          multiple={multiple}
          disabled={disabled}
          aria-labelledby={`${id}-label`}
          aria-describedby={hint ? `${id}-hint` : undefined}
          onChange={(e) => {
            const files = Array.from(e.target.files ?? []);
            setNames(files.map((file) => file.name));
            onFiles(files);
          }}
        />
        <span className="file-picker-button" aria-hidden="true">
          <Upload size={14} />
          {multiple ? "Choose files" : "Choose file"}
        </span>
        <span
          className={
            names.length ? "file-picker-name" : "file-picker-name empty"
          }
          aria-live="polite"
        >
          {chosen}
        </span>
      </span>
      {hint && (
        <small id={`${id}-hint`} className="muted">
          {hint}
        </small>
      )}
    </label>
  );
}
