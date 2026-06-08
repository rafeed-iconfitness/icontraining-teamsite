const crypto = require("node:crypto");
const nodemailer = require("nodemailer");

const HONEYPOT_FIELD = "companyWebsite";
const RATE_LIMIT_MESSAGE = "Too many requests. Please try again later.";
const HONEYPOT_MESSAGE = "Unable to submit. Please try again.";

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
  const inviteText = inviteUrl
    ? `Your next step is to join our Discord — that's where the team coordinates, shares resources, and where you'll get started on your first tasks.\n\nJoin here: ${inviteUrl}`
    : "Your next step is to join our Discord — we'll send your invite link in a follow-up email shortly.";

  const text = [
    "Hi there,",
    "",
    "Thanks for joining the Icon Training Growth Team! We're excited to have you on board.",
    "",
    inviteText,
    "",
    "See you inside,",
    "The Icon Training Team",
  ].join("\n");

  const inviteHtml = inviteUrl
    ? `
      <p>Your next step is to join our Discord — that's where the team coordinates, shares resources, and where you'll get started on your first tasks.</p>
      <p style="margin:28px 0">
        <a href="${escapeHtml(inviteUrl)}"
           style="display:inline-block;background:#FF5733;color:#fff;text-decoration:none;font-weight:700;padding:14px 28px;border-radius:8px">
          Join the Discord →
        </a>
      </p>
      <p style="color:#666;font-size:13px">If the button doesn't work, copy this link into your browser:<br>
        <a href="${escapeHtml(inviteUrl)}" style="color:#FF5733">${escapeHtml(inviteUrl)}</a>
      </p>`
    : `<p>Your next step is to join our Discord — we'll send your invite link in a follow-up email shortly.</p>`;

  const html = `
    <div style="font-family:Arial,Helvetica,sans-serif;color:#111;line-height:1.6;max-width:560px">
      <h2 style="margin:0 0 16px">Welcome to the Icon Training Growth Team 🎉</h2>
      <p>Hi there,</p>
      <p>Thanks for joining the Icon Training Growth Team! We're excited to have you on board.</p>
      ${inviteHtml}
      <p style="margin-top:28px">See you inside,<br><strong>The Icon Training Team</strong></p>
    </div>
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
