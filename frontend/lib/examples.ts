/**
 * "Try an example" inputs: the v1 scam types plus genuine ones, so people see a SAFE result
 * too. Names, numbers, UPI IDs and domains are made up.
 */

export type Example = { label: string; value: string; genuine?: boolean };

export const MESSAGE_EXAMPLES: Example[] = [
  {
    label: "Cashback “receive money”",
    value:
      "Congratulations! You have won ₹5,000 cashback from PhonePe. To receive the money, accept the payment request and enter your UPI PIN. Offer valid for 24 hours only.",
  },
  {
    label: "OLX buyer QR code",
    value:
      "Hi, I am interested in buying your sofa listed on OLX. I am sending ₹8,000 advance. Please scan this QR code and enter your UPI PIN to receive the payment.",
  },
  {
    label: "Sent by mistake",
    value:
      "Hello sir, I sent ₹3,000 to your Paytm by mistake while paying my son's school fees. Please return it to rohit.kumar77@ybl, it is urgent. God bless you.",
  },
  {
    label: "KYC / account blocked",
    value:
      "Dear Customer, your SBI YONO account will be BLOCKED today. Update your PAN/KYC immediately by clicking http://sbi-kyc-update.top/verify",
  },
  {
    label: "Electricity bill",
    value:
      "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please immediately call our electricity officer 9876543210.",
  },
  {
    label: "E-challan",
    value:
      "Your vehicle DL3CAB1234 has an unpaid e-challan of Rs 500. Pay now to avoid court action: https://echallan-parivahan.xyz/pay",
  },
  {
    label: "Part-time job",
    value:
      "Hi! We are hiring part-time. Earn ₹3,000-₹8,000 daily by liking YouTube videos from home. Just complete simple tasks. Contact on Telegram @hr_priya_jobs. Limited seats!",
  },
  {
    label: "Customer care",
    value:
      "Amazon Customer Care: your refund of ₹1,499 has failed. To receive it, call our helpline 8765432109 and install AnyDesk so our executive can help you.",
  },
  {
    label: "Genuine: food delivery",
    genuine: true,
    value:
      "Your Swiggy order #174839201756 from Meghana Foods is out for delivery. Suresh will reach in 12 mins. Total paid: ₹642.",
  },
];

export const LINK_EXAMPLES: Example[] = [
  { label: "Fake e-challan site", value: "https://echallan-parivahan.xyz/pay" },
  { label: "Parcel redelivery", value: "https://indiapost-redelivery.top/track" },
  { label: "Genuine: SBI", value: "https://www.onlinesbi.sbi", genuine: true },
];

export const UPI_EXAMPLES: Example[] = [
  { label: "“Refund” UPI ID", value: "refund.helpdesk@ybl" },
  { label: "Genuine: a shop", value: "sharmageneralstore@okaxis", genuine: true },
];

/** `value` is a file in public/. */
export const QR_EXAMPLES: Example[] = [
  { label: "Cashback QR", value: "/examples/qr-scam.png" },
  { label: "Genuine: shop QR", value: "/examples/qr-shop.png", genuine: true },
];

/** `value` is a file in public/ (rendered by backend/scripts/render_example_screenshots.py). */
export const SCREENSHOT_EXAMPLES: Example[] = [
  { label: "KYC SMS from a mobile number", value: "/examples/shot-sms-scam.png" },
  { label: "Fake payment proof", value: "/examples/shot-payment-proof.png" },
  { label: "Genuine: bank alert", value: "/examples/shot-bank-alert.png", genuine: true },
];
