const crypto = require("node:crypto");
const nodemailer = require("nodemailer");

const HONEYPOT_FIELD = "companyWebsite";
const RATE_LIMIT_MESSAGE = "Too many requests. Please try again later.";
const HONEYPOT_MESSAGE = "Unable to submit. Please try again.";
const ICON_LOGO_EMAIL_URL =
  "https://www.icontraining.app/versioned/brand/icon-logo-email-v1.png";

const rateLimitStore = new Map();

const requesterLimit = { limit: 5, windowMs: 60 * 60 * 1000 };
const emailLimit = { limit: 2, windowMs: 24 * 60 * 60 * 1000 };

function json(res, statusCode, payload) {
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(payload));
}

function hashValue(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function cleanupRateLimitStore(now) {
  for (const [key, bucket] of rateLimitStore) {
    const recentTimestamps = bucket.timestamps.filter(
      (timestamp) => timestamp > now - bucket.windowMs
    );

    if (recentTimestamps.length === 0) {
      rateLimitStore.delete(key);
      continue;
    }

    if (recentTimestamps.length !== bucket.timestamps.length) {
      rateLimitStore.set(key, {
        timestamps: recentTimestamps,
        windowMs: bucket.windowMs,
      });
    }
  }
}

function allowRequest(key, config, now) {
  const existingBucket = rateLimitStore.get(key);
  const recentTimestamps =
    existingBucket?.timestamps.filter(
      (timestamp) => timestamp > now - config.windowMs
    ) ?? [];

  if (recentTimestamps.length >= config.limit) {
    rateLimitStore.set(key, {
      timestamps: recentTimestamps,
      windowMs: config.windowMs,
    });
    return false;
  }

  recentTimestamps.push(now);
  rateLimitStore.set(key, {
    timestamps: recentTimestamps,
    windowMs: config.windowMs,
  });
  return true;
}

function getRequesterSource(req) {
  const forwardedFor = req.headers["x-forwarded-for"]?.split(",")[0]?.trim();

  return (
    req.headers["cf-connecting-ip"]?.trim() ||
    req.headers["x-real-ip"]?.trim() ||
    forwardedFor ||
    req.headers["user-agent"]?.trim() ||
    "unknown"
  );
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let rawBody = "";

    req.on("data", (chunk) => {
      rawBody += chunk;

      if (rawBody.length > 20_000) {
        reject(new Error("Request body too large"));
        req.destroy();
      }
    });

    req.on("end", () => {
      const contentType = req.headers["content-type"] || "";

      try {
        if (contentType.includes("application/json")) {
          resolve(JSON.parse(rawBody || "{}"));
          return;
        }

        const params = new URLSearchParams(rawBody);
        resolve(Object.fromEntries(params.entries()));
      } catch (error) {
        reject(error);
      }
    });

    req.on("error", reject);
  });
}

let cachedTransporter = null;

function getTransporter() {
  if (!cachedTransporter) {
    cachedTransporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD,
      },
    });
  }

  return cachedTransporter;
}

function buildInviteEmail({ inviteUrl }) {
  const text = [
    "Thanks for expressing an interest in joining the Icon Training Growth Team.",
    "",
    "Join the Discord server, attend onboarding, contribute, succeed.",
    "",
    inviteUrl
      ? `Join the Growth Team:\n${inviteUrl}`
      : "We'll send your Discord invite link in a follow-up email shortly.",
  ].join("\n");

  const ctaHtml = inviteUrl
    ? `
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="width:100%;">
                      <tr>
                        <td>
                          <a href="${escapeHtml(inviteUrl)}" style="display:block;background:#FF5733;border-radius:10px;color:#050505;font-size:16px;line-height:20px;font-weight:700;text-align:center;text-decoration:none;padding:15px 18px;">
                            Join the Growth Team
                          </a>
                        </td>
                      </tr>
                    </table>
                    <p style="margin:26px 0 0 0;color:#777777;font-size:13px;line-height:21px;">
                      If the button does not open, copy this link into your browser:<br>
                      <a href="${escapeHtml(inviteUrl)}" style="color:#FFB29F;text-decoration:underline;">${escapeHtml(inviteUrl)}</a>
                    </p>`
    : `
                    <p style="margin:0;color:#b8b8b8;font-size:16px;line-height:26px;">
                      We'll send your Discord invite link in a follow-up email shortly.
                    </p>`;

  const html = `
    <!doctype html>
    <html>
      <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to the Icon Training Growth Team</title>
      </head>
      <body style="margin:0;padding:0;background:#050505;color:#ffffff;font-family:Arial,Helvetica,sans-serif;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;background:#050505;margin:0;padding:0;">
          <tr>
            <td align="center" style="padding:32px 16px;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;max-width:600px;border-collapse:separate;">
                <tr>
                  <td style="padding:0 0 18px 0;">
                    <img src="${ICON_LOGO_EMAIL_URL}" width="96" height="52" alt="Icon Training" style="display:block;width:96px;height:52px;border:0;outline:none;text-decoration:none;">
                  </td>
                </tr>
                <tr>
                  <td style="background:#0d0d0d;border:1px solid #242424;border-radius:18px;padding:34px 28px;">
                    <div style="display:inline-block;margin:0 0 22px 0;padding:7px 12px;border:1px solid rgba(255,87,51,0.35);border-radius:999px;background:rgba(255,87,51,0.12);color:#FFB29F;font-size:12px;line-height:16px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;">
                      Growth Team Request
                    </div>
                    <h1 style="margin:0 0 18px 0;color:#ffffff;font-size:32px;line-height:38px;font-weight:800;letter-spacing:0;">
                      Thanks for expressing an interest in joining the Icon Training Growth Team
                    </h1>
                    <p style="margin:0 0 26px 0;color:#b8b8b8;font-size:16px;line-height:26px;">
                      Join the Discord server, attend onboarding, contribute, succeed.
                    </p>
                    ${ctaHtml}
                  </td>
                </tr>
                <tr>
                  <td style="padding:18px 4px 0 4px;color:#777777;font-size:12px;line-height:18px;text-align:center;">
                    Icon Training
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
    </html>
  `;

  return { text, html };
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    json(res, 405, { success: false, message: "Method not allowed" });
    return;
  }

  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    console.error("Missing GMAIL_USER or GMAIL_APP_PASSWORD");
    json(res, 500, { success: false, message: "Internal server error" });
    return;
  }

  let body;

  try {
    body = await parseBody(req);
  } catch (error) {
    json(res, 400, { success: false, message: "Invalid submission" });
    return;
  }

  if (typeof body[HONEYPOT_FIELD] === "string" && body[HONEYPOT_FIELD].trim()) {
    json(res, 400, { success: false, message: HONEYPOT_MESSAGE });
    return;
  }

  const email = String(body.email || "").trim().toLowerCase();

  if (!isValidEmail(email)) {
    json(res, 400, { success: false, message: "Enter a valid email address" });
    return;
  }

  const now = Date.now();
  cleanupRateLimitStore(now);

  const requesterKey = `growth:requester:${hashValue(getRequesterSource(req))}`;

  if (!allowRequest(requesterKey, requesterLimit, now)) {
    json(res, 429, { success: false, message: RATE_LIMIT_MESSAGE });
    return;
  }

  const emailKey = `growth:email:${hashValue(email)}`;

  if (!allowRequest(emailKey, emailLimit, now)) {
    json(res, 429, { success: false, message: RATE_LIMIT_MESSAGE });
    return;
  }

  const fromAddress = `Icon Training <${process.env.GMAIL_USER}>`;
  const inviteUrl = (process.env.DISCORD_INVITE_URL || "").trim();

  if (!inviteUrl) {
    console.warn("DISCORD_INVITE_URL is not set — the email will omit the invite link.");
  }

  try {
    const transporter = getTransporter();
    const invite = buildInviteEmail({ inviteUrl });

    await transporter.sendMail({
      from: fromAddress,
      to: email,
      subject: "Welcome to the Icon Training Growth Team",
      text: invite.text,
      html: invite.html,
    });

    json(res, 200, {
      success: true,
      message: "Check your email for your Discord invite!",
    });
  } catch (error) {
    console.error("Application submission error:", error);
    json(res, 500, {
      success: false,
      message: "Something went wrong. Please try again.",
    });
  }
};
