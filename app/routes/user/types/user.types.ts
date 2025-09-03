export interface CreateUserRequest {
    email: string;
  }
  
  export interface LoginRequest {
    email: string;
    password: string;
  }
  
  export interface UserResponse {
    id: string;
    email: string;
    name: string;
    emailVerified: boolean;
    createdAt: Date;
    updatedAt: Date;
  }
  
  export interface AuthResponse {
    success: boolean;
    message: string;
    user?: UserResponse;
    token?: string;
    loginPassword?: string;
    masterPassword?: string;
    error?: string;
  }
  
  export interface VerifyEmailRequest {
    token: string;
  }
  
  export interface ResetPasswordRequest {
    email: string;
  }
  
  export interface ConfirmResetPasswordRequest {
    token: string;
    password: string;
  }
  
  export interface UpdateProfileRequest {
    name?: string;
  }
  
  export interface ChangePasswordRequest {
    currentPassword: string;
    newPassword: string;
  }
  
  export interface SessionData {
    userId: string;
    email: string;
    name: string;
    sessionId: string;
  }
  
  export interface GeneratedPasswords {
    loginPassword: string;
    masterPassword: string;
  }
  