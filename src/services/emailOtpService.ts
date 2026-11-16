import crypto from "crypto";
import bcrypt from "bcryptjs";
import adminDb from "../config/firebase";
import logger from "../config/logger";
import { env } from "../config/env";

export interface EmailOtpSession {
  uid: string;
  email: string;
  hashedOtp: string;
  type: string;
  channel: string;
  verified: boolean;
  attempts: number;
  createdAt: string;
  expiresAt: string;
  cooldownUntil: string;
}

function escapeHtml(str: string): string {
  return str.replace(/[&<>"']/g, (match) => {
    const map: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;",
    };
    return map[match] || match;
  });
}

function sanitizeLogMessage(message: string, apiKey?: string): string {
  if (!apiKey || !message) return message;
  const cleanKey = apiKey.trim().replace(/^["']|["']$/g, "");
  if (!cleanKey) return message;
  return message.split(cleanKey).join("[REDACTED_API_KEY]");
}

function resolveWhatsApiEmailEndpoint(rawUrl: string): string {
  let cleaned = (rawUrl || "").trim().replace(/^["']|["']$/g, "").replace(/\/+$/, "");
  if (!cleaned) return "";

  if (cleaned.endsWith("/api/email/send")) return cleaned;
  if (cleaned.endsWith("/api/email")) return `${cleaned}/send`;
  if (cleaned.endsWith("/api")) return `${cleaned}/email/send`;
  return `${cleaned}/api/email/send`;
}

export class EmailOtpService {
  /**
   * Generates a cryptographically secure 6-digit OTP string
   */
  private static generateOtp(): string {
    return crypto.randomInt(100000, 1000000).toString();
  }

  /**
   * Sends a PIN Reset OTP via the WhatsAPI HUB Email API to the user's registered email.
   */
  public static async sendPinResetOtp(uid: string, authEmail?: string): Promise<{ message: string; devOtp?: string }> {
    const isProd = env.NODE_ENV === "production";
    const emailApiUrl = env.EMAIL_API_URL;
    const emailApiKey = env.EMAIL_API_KEY;
    const emailInstanceId = env.EMAIL_INSTANCE_ID || "";

    if (!emailApiUrl || !emailApiKey) {
      logger.error("[EmailOtpService] Configuration Error: EMAIL_API_URL or EMAIL_API_KEY is missing.");
      throw new Error("Email service configuration is incomplete. Please contact support.");
    }

    if (!adminDb) {
      throw new Error("Firestore Admin Database not initialized.");
    }

    logger.info(`[EmailOtpService] Looking up email for authenticated uid: ${uid}`);

    // Retrieve user's registered email and profile details from Firestore or decoded Auth token
    const userSnap = await adminDb.collection("users").doc(uid).get();
    const userData = userSnap.exists ? userSnap.data() : null;

    if (!userSnap.exists) {
      logger.warn(`[EmailOtpService] Profile document users/${uid} does not exist in Firestore.`);
    } else {
      logger.info(`[EmailOtpService] Profile document users/${uid} retrieved successfully.`);
    }

    const resolvedEmail = (userData?.email || userData?.emailAddress || userData?.userEmail || authEmail || "").trim();

    if (!resolvedEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(resolvedEmail)) {
      logger.error(`[EmailOtpService] Email resolution failed for uid ${uid}. No valid email in Firestore doc or auth token.`);
      throw new Error("No valid registered email address found on this profile.");
    }

    logger.info(`[EmailOtpService] Registered email found; preparing Email OTP dispatch.`);
    const userEmail = resolvedEmail;

    const docId = `pin_reset_email_${uid}`;
    const sessionDocRef = adminDb.collection("otp_sessions").doc(docId);
    const sessionSnap = await sessionDocRef.get();
    const now = new Date();

    // Check resend cooldown (60 seconds)
    if (sessionSnap.exists) {
      const data = sessionSnap.data() as EmailOtpSession;
      if (data && data.cooldownUntil) {
        const cooldownTime = new Date(data.cooldownUntil);
        if (now < cooldownTime) {
          const waitSec = Math.ceil((cooldownTime.getTime() - now.getTime()) / 1000);
          throw new Error(`Rate limit exceeded. Please wait ${waitSec}s before requesting a new OTP.`);
        }
      }
    }

    // Generate 6-digit OTP using crypto.randomInt and hash with bcrypt
    const rawOtp = this.generateOtp();
    const hashedOtp = await bcrypt.hash(rawOtp, 10);

    const expiresAt = new Date(now.getTime() + 10 * 60 * 1000).toISOString(); // 10 minutes
    const cooldownUntil = new Date(now.getTime() + 60 * 1000).toISOString(); // 60 seconds

    const newSession: EmailOtpSession = {
      uid,
      email: userEmail.toLowerCase(),
      hashedOtp,
      type: "pin_reset",
      channel: "email",
      verified: false,
      attempts: 0,
      createdAt: now.toISOString(),
      expiresAt,
      cooldownUntil,
    };

    // Store session first so cooldown and state are tracked
    await sessionDocRef.set(newSession);

    // Prepare email content with HTML escaping for user display name
    const rawName = userData?.fullName || userData?.firstName || userData?.displayName || "Valued Customer";
    const escapedName = escapeHtml(rawName);

    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #FC7A00; margin-bottom: 16px;">E-Global Pay</h2>
        <p>Hello ${escapedName},</p>
        <p>Your one-time passcode (OTP) for PIN reset is:</p>
        <div style="background-color: #f4f4f4; padding: 15px; font-size: 24px; font-weight: bold; text-align: center; letter-spacing: 5px; color: #333; margin: 20px 0; border-radius: 4px;">
          ${rawOtp}
        </div>
        <p>This code will expire in 10 minutes. Do not share this code with anyone.</p>
        <p style="color: #777; font-size: 12px; margin-top: 24px;">If you did not request a PIN reset, please ignore this email or contact support.</p>
      </div>
    `;

    const sendEndpoint = resolveWhatsApiEmailEndpoint(emailApiUrl);
    const cleanApiKey = (emailApiKey || "").trim().replace(/^["']|["']$/g, "");
    const cleanInstanceId = (emailInstanceId || "").trim().replace(/^["']|["']$/g, "");

    logger.info(`[EmailOtpService] Target WhatsAPI Email endpoint resolved: ${sendEndpoint}`);

    let sendSuccess = false;
    let apiErrorLog = "";

    const maxAttempts = 2;
    for (let attempt = 1; attempt <= maxAttempts && !sendSuccess; attempt++) {
      try {
        logger.info(`[EmailOtpService] Dispatching PIN reset OTP email to ${userEmail} (Attempt ${attempt}/${maxAttempts})...`);

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 20000); // 20-second timeout per attempt

        const headers: Record<string, string> = {
          "Content-Type": "application/json",
          "X-API-Key": cleanApiKey,
          "Authorization": `Bearer ${cleanApiKey}`,
        };

        if (cleanInstanceId) {
          headers["X-Instance-ID"] = cleanInstanceId;
          headers["X-Project-ID"] = cleanInstanceId;
        }

        const res = await fetch(sendEndpoint, {
          method: "POST",
          headers,
          body: JSON.stringify({
            to: userEmail,
            subject: "Your E-Global Pay OTP",
            html: htmlContent,
          }),
          signal: controller.signal,
        }).finally(() => clearTimeout(timeoutId));

        if (res.ok) {
          sendSuccess = true;
          logger.info(`[EmailOtpService] OTP email successfully delivered to ${userEmail}.`);
        } else {
          const textResp = await res.text().catch(() => "");
          const sanitizedResp = sanitizeLogMessage(textResp, cleanApiKey);
          apiErrorLog = `HTTP ${res.status}: ${sanitizedResp}`;
          logger.error(`[EmailOtpService] Email API returned error status | ${apiErrorLog}`);

          // Do NOT retry 400, 401, 403, or 429 permanent errors
          if ([400, 401, 403, 429].includes(res.status)) {
            break;
          }
        }
      } catch (err: any) {
        if (err.name === "AbortError") {
          apiErrorLog = "Email API dispatch timed out after 20 seconds.";
        } else {
          const causeMsg = err.cause ? ` | Cause: ${err.cause.message || err.cause.code || JSON.stringify(err.cause)}` : "";
          const rawErr = `${err.message || "Network request failed"}${causeMsg}`;
          apiErrorLog = sanitizeLogMessage(rawErr, cleanApiKey);
        }
        logger.error(`[EmailOtpService] Email API dispatch exception (Attempt ${attempt}): ${apiErrorLog}`);
      }

      if (!sendSuccess && attempt < maxAttempts) {
        logger.info(`[EmailOtpService] Retrying email dispatch in 2 seconds...`);
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
    }

    if (!sendSuccess) {
      // Delivery failed: immediately delete newly created OTP session to prevent undelivered active sessions
      await sessionDocRef.delete().catch((delErr) => {
        logger.error(`[EmailOtpService] Failed to cleanup session after email dispatch error: ${delErr.message}`);
      });
      throw new Error("Failed to deliver OTP email. Please try again later.");
    }

    // Audit Log Entry
    await adminDb.collection("otp_audits").add({
      uid,
      email: userEmail,
      channel: "email",
      type: "pin_reset",
      action: "GENERATE",
      status: "SUCCESS",
      timestamp: now.toISOString(),
    });

    if (!isProd) {
      logger.info(`[EmailOtpService] [DEV MODE] Email OTP code: ${rawOtp} for ${userEmail}`);
      return {
        message: "PIN reset OTP sent to registered email address.",
        devOtp: rawOtp,
      };
    }

    return {
      message: "PIN reset OTP sent to registered email address.",
    };
  }

  /**
   * Verifies an Email PIN Reset OTP code submitted by the user.
   */
  public static async verifyPinResetOtp(uid: string, otpCode: string): Promise<{ success: boolean; message: string }> {
    if (!adminDb) {
      throw new Error("Firestore Admin Database not initialized.");
    }

    const docId = `pin_reset_email_${uid}`;
    const sessionDocRef = adminDb.collection("otp_sessions").doc(docId);
    const sessionSnap = await sessionDocRef.get();

    if (!sessionSnap.exists) {
      throw new Error("No active email verification session found. Please request a new OTP.");
    }

    const data = sessionSnap.data() as EmailOtpSession;
    const now = new Date();

    // Verify channel restriction: A WhatsApp OTP must NEVER be accepted by the Email OTP path
    if (data.channel !== "email") {
      throw new Error("Invalid session channel for email verification.");
    }

    // Check expiration (10 minutes)
    if (now > new Date(data.expiresAt)) {
      await sessionDocRef.delete();
      throw new Error("Verification code has expired. Please request a new OTP.");
    }

    // Compare submitted OTP using bcrypt.compare
    const isMatch = await bcrypt.compare(otpCode.trim(), data.hashedOtp);

    if (!isMatch) {
      const updatedAttempts = (data.attempts || 0) + 1;

      await adminDb.collection("otp_audits").add({
        uid,
        email: data.email,
        channel: "email",
        type: "pin_reset",
        action: "VERIFY_FAILED",
        timestamp: now.toISOString(),
        attemptCount: updatedAttempts,
      });

      if (updatedAttempts >= 3) {
        // Third failure: immediately delete/invalidate session permanently
        await sessionDocRef.delete();
        throw new Error("Too many failed attempts. This OTP session has been terminated. Please generate a new OTP.");
      } else {
        await sessionDocRef.update({ attempts: updatedAttempts });
        const remaining = 3 - updatedAttempts;
        throw new Error(`Incorrect verification code. You have ${remaining} attempts remaining before lockout.`);
      }
    }

    // Successful verification: mark session as verified and extend expiry so final PIN reset step can consume it
    await sessionDocRef.update({
      verified: true,
      expiresAt: new Date(now.getTime() + 15 * 60 * 1000).toISOString(),
    });

    // Audit Log for success
    await adminDb.collection("otp_audits").add({
      uid,
      email: data.email,
      channel: "email",
      type: "pin_reset",
      action: "VERIFY_SUCCESS",
      timestamp: now.toISOString(),
    });

    return {
      success: true,
      message: "Email OTP verified successfully.",
    };
  }

  /**
   * Sends a signup email OTP using ONLY the backend VM environment credentials.
   * The CPANEL email_connect document is intentionally never consulted here.
   */
  public static async sendSignupOtp(email: string): Promise<{ message: string; devOtp?: string }> {
    const isProd = env.NODE_ENV === "production";
    const emailApiUrl = env.EMAIL_API_URL;
    const emailApiKey = env.EMAIL_API_KEY;
    const emailInstanceId = env.EMAIL_INSTANCE_ID || "";

    const normalizedEmail = String(email || "").trim().toLowerCase();
    if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(normalizedEmail)) {
      throw new Error("Please enter a valid email address.");
    }
    if (!emailApiUrl || !emailApiKey) {
      logger.error("[EmailOtpService] VM email configuration is incomplete.");
      throw new Error("VM email service is not configured. Please contact support.");
    }
    if (!adminDb) throw new Error("Firestore Admin Database not initialized.");

    const now = new Date();
    const nowMs = now.getTime();
    const cooldownRef = adminDb.collection("otp_cooldowns").doc(`signup_email_${normalizedEmail}`);
    const cooldownSnap = await cooldownRef.get();
    if (cooldownSnap.exists) {
      const lastSentAt = Number(cooldownSnap.data()?.lastSentAt || 0);
      if (nowMs - lastSentAt < 60000) {
        const remaining = Math.ceil((60000 - (nowMs - lastSentAt)) / 1000);
        throw new Error(`Please wait ${remaining} seconds before requesting another email verification code.`);
      }
    }

    const rawOtp = this.generateOtp();
    const hashedOtp = await bcrypt.hash(rawOtp, 10);
    const expiresAtMs = nowMs + 5 * 60 * 1000;
    const otpRef = adminDb.collection("signup_email_otps").doc(normalizedEmail);
    await otpRef.set({
      email: normalizedEmail,
      otpHash: hashedOtp,
      hashAlgorithm: "bcrypt",
      attempts: 0,
      consumed: false,
      verified: false,
      createdAtMs: nowMs,
      expiresAtMs,
      createdAt: now.toISOString(),
    });

    const endpoint = resolveWhatsApiEmailEndpoint(emailApiUrl);
    const cleanKey = emailApiKey.trim().replace(/^[\"']|[\"']$/g, "");
    const cleanInstance = emailInstanceId.trim().replace(/^[\"']|[\"']$/g, "");
    const safeEmail = escapeHtml(normalizedEmail);
    const html = `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;border:1px solid #e5e7eb;border-radius:12px">
        <h2 style="color:#FC7A00">E-Global Pay Account Verification</h2>
        <p>Hello,</p><p>Use this 6-digit code to verify your email address:</p>
        <div style="padding:16px;background:#f4f4f4;text-align:center;font-size:28px;font-weight:bold;letter-spacing:8px">${rawOtp}</div>
        <p>This code expires in 5 minutes. Do not share it with anyone.</p>
        <p style="color:#777;font-size:12px">If you did not request this code, you can ignore this email.</p>
      </div>`;

    let delivered = false;
    let lastError = "";
    for (let attempt = 1; attempt <= 2 && !delivered; attempt++) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 20000);
      try {
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
          "X-API-Key": cleanKey,
          "Authorization": `Bearer ${cleanKey}`,
        };
        if (cleanInstance) {
          headers["X-Instance-ID"] = cleanInstance;
          headers["X-Project-ID"] = cleanInstance;
        }
        const response = await fetch(endpoint, {
          method: "POST",
          headers,
          body: JSON.stringify({
            to: normalizedEmail,
            subject: "Welcome to E-Global Pay - Email Verification Code",
            html,
          }),
          signal: controller.signal,
        });
        if (response.ok) {
          delivered = true;
        } else {
          const responseText = await response.text().catch(() => "");
          lastError = `Email provider returned HTTP ${response.status}: ${sanitizeLogMessage(responseText, cleanKey)}`;
          logger.error(`[EmailOtpService] Signup email dispatch failed: ${lastError}`);
          if ([400, 401, 403, 429].includes(response.status)) break;
        }
      } catch (error: any) {
        lastError = error?.name === "AbortError" ? "Email provider request timed out." : sanitizeLogMessage(error?.message || "Network error", cleanKey);
        logger.error(`[EmailOtpService] Signup email dispatch exception: ${lastError}`);
      } finally {
        clearTimeout(timeout);
      }
      if (!delivered && attempt < 2) await new Promise(resolve => setTimeout(resolve, 1000));
    }

    if (!delivered) {
      await otpRef.delete().catch(() => undefined);
      throw new Error("Failed to deliver email verification code. Please try again later.");
    }

    await cooldownRef.set({ email: normalizedEmail, lastSentAt: nowMs, updatedAt: now.toISOString() });
    await adminDb.collection("otp_audits").add({
      email: normalizedEmail, channel: "email", type: "signup",
      action: "GENERATE", status: "SUCCESS", timestamp: now.toISOString(),
    });

    return {
      message: "Verification code sent to your email address successfully!",
      ...(!isProd ? { devOtp: rawOtp } : {}),
    };
  }

  /**
   * Verifies a signup email OTP on the backend VM. Supports legacy HMAC sessions
   * only for a short migration window; new sessions use bcrypt.
   */
  public static async verifySignupOtp(email: string, otpCode: string): Promise<{ success: boolean; message: string }> {
    if (!adminDb) throw new Error("Firestore Admin Database not initialized.");
    const normalizedEmail = String(email || "").trim().toLowerCase();
    const submittedOtp = String(otpCode || "").trim();
    if (!/^[0-9]{6}$/.test(submittedOtp)) throw new Error("A valid 6-digit OTP code is required.");

    const otpRef = adminDb.collection("signup_email_otps").doc(normalizedEmail);
    const snap = await otpRef.get();
    if (!snap.exists) throw new Error("Verification code not found or expired. Please request a new code.");
    const data = snap.data() || {};
    const now = Date.now();

    if (data.consumed === true) throw new Error("This verification code has already been used. Please request a new code.");
    if (!data.expiresAtMs || now > Number(data.expiresAtMs)) {
      await otpRef.delete().catch(() => undefined);
      throw new Error("Verification code has expired. Please request a new code.");
    }
    const attempts = Number(data.attempts || 0);
    if (attempts >= 3) throw new Error("Too many failed attempts. Please request a new verification code.");

    let valid = false;
    if (data.hashAlgorithm === "bcrypt" || String(data.otpHash || "").startsWith("$2")) {
      valid = await bcrypt.compare(submittedOtp, String(data.otpHash || ""));
    } else if (data.otpHash) {
      // Backward compatibility for sessions created before the VM migration.
      const secret = process.env.CPANEL_SESSION_SECRET || process.env.JWT_SECRET || "signup_otp_secret_key";
      const legacyHash = crypto.createHmac("sha256", secret).update(submittedOtp).digest("hex");
      valid = data.otpHash === legacyHash;
    } else {
      valid = data.otpCode === submittedOtp;
    }

    if (!valid) {
      const nextAttempts = attempts + 1;
      await otpRef.update({ attempts: nextAttempts });
      await adminDb.collection("otp_audits").add({
        email: normalizedEmail, channel: "email", type: "signup",
        action: "VERIFY_FAILED", attemptCount: nextAttempts, timestamp: new Date().toISOString(),
      });
      throw new Error(`Incorrect verification code. You have ${Math.max(0, 3 - nextAttempts)} attempt(s) remaining.`);
    }

    await otpRef.update({ consumed: true, verified: true, consumedAt: new Date().toISOString() });
    await adminDb.collection("otp_audits").add({
      email: normalizedEmail, channel: "email", type: "signup",
      action: "VERIFY_SUCCESS", timestamp: new Date().toISOString(),
    });
    return { success: true, message: "Email address verified successfully!" };
  }

}
