const crypto = require("node:crypto");

const MAILERLITE_API_URL = "https://connect.mailerlite.com/api/subscribers";
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

async function submitToMailerLite({ email, groupId, fields }) {
  const payload = {
    email,
    groups: [groupId],
  };

  if (Object.keys(fields).length > 0) {
    payload.fields = fields;
  }

  const response = await fetch(MAILERLITE_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.MAIL_API_KEY}`,
    },
    body: JSON.stringify(payload),
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    return {
      success: false,
      message: data?.message || "Failed to submit application",
    };
  }

  return { success: true };
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    json(res, 405, { success: false, message: "Method not allowed" });
    return;
  }

  if (!process.env.MAIL_API_KEY) {
    console.error("Missing MAIL_API_KEY");
    json(res, 500, { success: false, message: "Internal server error" });
    return;
  }

  const groupId =
    process.env.MAIL_GROWTH_TEAM_GROUP_ID || process.env.MAIL_TRAINER_GROUP_ID;

  if (!groupId) {
    console.error("Missing MAIL_GROWTH_TEAM_GROUP_ID or MAIL_TRAINER_GROUP_ID");
    json(res, 500, { success: false, message: "Configuration error" });
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

  const fields = {
    name: `${firstName} ${lastName}`,
  };
  const roleFieldKey = process.env.MAIL_GROWTH_ROLE_FIELD_KEY;

  if (roleFieldKey) {
    fields[roleFieldKey] = role;
  }

  try {
    const submission = await submitToMailerLite({ email, groupId, fields });

    if (!submission.success) {
      json(res, 502, {
        success: false,
        message: submission.message || "Failed to submit application",
      });
      return;
    }

    json(res, 200, {
      success: true,
      message: "Application submitted successfully!",
    });
  } catch (error) {
    console.error("Application submission error:", error);
    json(res, 500, {
      success: false,
      message: "Something went wrong. Please try again.",
    });
  }
};
