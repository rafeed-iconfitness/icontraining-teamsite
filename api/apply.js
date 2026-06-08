const crypto = require("node:crypto");
const nodemailer = require("nodemailer");

const HONEYPOT_FIELD = "companyWebsite";
const RATE_LIMIT_MESSAGE = "Too many requests. Please try again later.";
const HONEYPOT_MESSAGE = "Unable to submit. Please try again.";
const DEFAULT_NOTIFY_EMAIL = "mish@icontraining.app";

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

function buildNotificationEmail({ firstName, lastName, email, role }) {
  const fullName = `${firstName} ${lastName}`;
  const text = [
    "New Growth Team application",
    "",
    `Name:  ${fullName}`,
    `Email: ${email}`,
    `Role:  ${role}`,
  ].join("\n");

  const html = `
    <div style="font-family:Arial,Helvetica,sans-serif;color:#111;line-height:1.6">
      <h2 style="margin:0 0 16px">New Growth Team application</h2>
      <table style="border-collapse:collapse">
        <tr><td style="padding:4px 16px 4px 0;color:#666">Name</td><td style="padding:4px 0"><strong>${escapeHtml(
          fullName
        )}</strong></td></tr>
        <tr><td style="padding:4px 16px 4px 0;color:#666">Email</td><td style="padding:4px 0"><a href="mailto:${escapeHtml(
          email
        )}">${escapeHtml(email)}</a></td></tr>
        <tr><td style="padding:4px 16px 4px 0;color:#666">Role</td><td style="padding:4px 0">${escapeHtml(
          role
        )}</td></tr>
      </table>
    </div>
  `;

  return { text, html };
}

function buildWelcomeEmail({ firstName, inviteUrl }) {
  const greetingName = firstName || "there";

  const inviteText = inviteUrl
    ? `Your next step is to join our Discord — that's where the team coordinates, shares resources, and where you'll get started on your first tasks.\n\nJoin here: ${inviteUrl}`
    : "Your next step is to join our Discord — we'll send your invite link in a follow-up email shortly.";

  const text = [
    `Hi ${greetingName},`,
    "",
    "Thanks for applying to the Icon Training Growth Team! We're excited to have you on board.",
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
      <p>Hi ${escapeHtml(greetingName)},</p>
      <p>Thanks for applying to the Icon Training Growth Team! We're excited to have you on board.</p>
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

  const firstName = String(body.firstName || "").trim();
  const lastName = String(body.lastName || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const role = String(body.role || "").trim();

  if (!firstName) {
    json(res, 400, { success: false, message: "First name is required" });
    return;
  }

  if (!lastName) {
    json(res, 400, { success: false, message: "Last name is required" });
    return;
  }

  if (!isValidEmail(email)) {
    json(res, 400, { success: false, message: "Enter a valid email address" });
    return;
  }

  if (!role) {
    json(res, 400, { success: false, message: "Please choose a role" });
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
  const notifyEmail = process.env.NOTIFY_EMAIL || DEFAULT_NOTIFY_EMAIL;
  const inviteUrl = (process.env.DISCORD_INVITE_URL || "").trim();

  if (!inviteUrl) {
    console.warn("DISCORD_INVITE_URL is not set — applicant email will omit the invite link.");
  }

  try {
    const transporter = getTransporter();

    // Notify the team first so the lead is always captured.
    const notification = buildNotificationEmail({
      firstName,
      lastName,
      email,
      role,
    });

    await transporter.sendMail({
      from: fromAddress,
      to: notifyEmail,
      replyTo: email,
      subject: `New Growth Team application — ${firstName} ${lastName} (${role})`,
      text: notification.text,
      html: notification.html,
    });

    // Send the applicant their welcome + Discord invite. Best-effort: a
    // failure here shouldn't fail the submission the team already received.
    try {
      const welcome = buildWelcomeEmail({ firstName, inviteUrl });

      await transporter.sendMail({
        from: fromAddress,
        to: email,
        replyTo: notifyEmail,
        subject: "Welcome to the Icon Training Growth Team",
        text: welcome.text,
        html: welcome.html,
      });
    } catch (welcomeError) {
      console.error("Failed to send applicant welcome email:", welcomeError);
    }

    json(res, 200, {
      success: true,
      message: "Application submitted! Check your email for your Discord invite.",
    });
  } catch (error) {
    console.error("Application submission error:", error);
    json(res, 500, {
      success: false,
      message: "Something went wrong. Please try again.",
    });
  }
};
