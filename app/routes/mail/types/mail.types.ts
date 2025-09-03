export interface SendMailRequest {
    email: string;
    subject: string;
    content: string;
  }
  
  export interface MailResponse {
    success: boolean;
    messageId?: string;
    message: string;
    error?: string;
  }
  
  export interface WelcomeEmailData {
    name: string;
    email: string;
    password: string;
    masterPassword: string;
  }
  
  export interface LoginNotificationData {
    name: string;
    loginTime: string;
    ip: string;
    browser: string;
  }
  
  export interface ResetPasswordData {
    reset_url: string;
  }
  