// qrcode.go — QR code helpers for TOTP provisioning.
//
// We render QR codes entirely client-side using qrcodejs (loaded from cdnjs)
// so there are no external image requests and no dependency on Google Charts.
// The raw secret and full otpauth:// URI are always shown as text fallback.
package auth

// QRCodeCDN is the qrcodejs library URL from cdnjs.
// cdnjs is already trusted in our CSP for Tailwind; no additional changes needed.
const QRCodeCDN = "https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"
