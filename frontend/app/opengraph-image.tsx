import { ImageResponse } from "next/og";

export const alt = "Kavach — Pehle check karo, phir pay karo.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

// Social preview card, rendered at build time.
export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          padding: 80,
          background: "#FBF8F1",
          color: "#111111",
          fontFamily: "sans-serif",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <svg width="88" height="88" viewBox="0 0 32 32">
            <path
              d="M16 2.5 4.5 7v8.2c0 7.1 4.9 12.4 11.5 14.3 6.6-1.9 11.5-7.2 11.5-14.3V7L16 2.5Z"
              fill="#4338CA"
              stroke="#111"
              strokeWidth="2.2"
              strokeLinejoin="round"
            />
            <path
              d="m10.5 16 3.8 3.8 7.4-7.6"
              fill="none"
              stroke="#fff"
              strokeWidth="3"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <div style={{ fontSize: 64, fontWeight: 800 }}>Kavach</div>
        </div>
        <div style={{ display: "flex", marginTop: 48, fontSize: 84, fontWeight: 800, lineHeight: 1.1 }}>
          Pehle&nbsp;
          <span
            style={{
              background: "#4338CA",
              color: "#fff",
              border: "4px solid #111",
              borderRadius: 20,
              padding: "0 16px",
              boxShadow: "6px 6px 0 #111",
            }}
          >
            check
          </span>
          &nbsp;karo,
        </div>
        <div style={{ fontSize: 84, fontWeight: 800, lineHeight: 1.1, marginTop: 12 }}>
          phir pay karo.
        </div>
        <div style={{ marginTop: 40, fontSize: 34, color: "#3f3f46" }}>
          AI scam checker for SMS, links, UPI IDs and QR codes — in English and Hindi.
        </div>
      </div>
    ),
    size,
  );
}
