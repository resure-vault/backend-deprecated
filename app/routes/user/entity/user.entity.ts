export interface User {
    id: string;
    email: string;
    name: string;
    password: string;
    masterPassword: string;
    emailVerified: boolean;
    emailVerificationToken?: string;
    resetPasswordToken?: string;
    resetPasswordExpires?: Date;
    createdAt: Date;
    updatedAt: Date;
  }
  
  export interface Session {
    id: string;
    userId: string;
    token: string;
    expiresAt: Date;
    createdAt: Date;
  }
  
  export interface UserProfile {
    id: string;
    userId: string;
    avatar?: string;
    bio?: string;
    phone?: string;
    lastLoginAt?: Date;
    loginCount: number;
    createdAt: Date;
    updatedAt: Date;
  }
  