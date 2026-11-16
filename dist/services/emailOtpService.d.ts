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
export declare class EmailOtpService {
    /**
     * Generates a cryptographically secure 6-digit OTP string
     */
    private static generateOtp;
    /**
     * Sends a PIN Reset OTP via the WhatsAPI HUB Email API to the user's registered email.
     */
    static sendPinResetOtp(uid: string, authEmail?: string): Promise<{
        message: string;
        devOtp?: string;
    }>;
    /**
     * Verifies an Email PIN Reset OTP code submitted by the user.
     */
    static verifyPinResetOtp(uid: string, otpCode: string): Promise<{
        success: boolean;
        message: string;
    }>;
    /**
     * Sends a signup email OTP using ONLY the backend VM environment credentials.
     * The CPANEL email_connect document is intentionally never consulted here.
     */
    static sendSignupOtp(email: string): Promise<{
        message: string;
        devOtp?: string;
    }>;
    /**
     * Verifies a signup email OTP on the backend VM. Supports legacy HMAC sessions
     * only for a short migration window; new sessions use bcrypt.
     */
    static verifySignupOtp(email: string, otpCode: string): Promise<{
        success: boolean;
        message: string;
    }>;
    /**
     * Dispatches a caller-generated OTP for security flows whose session is managed
     * by the application. Delivery credentials always come from backend VM env.
     */
    static sendRawOtp(to: string, otp: string, purpose: string): Promise<void>;
}
