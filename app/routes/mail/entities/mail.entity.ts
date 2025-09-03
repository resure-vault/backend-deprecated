export interface EmailTemplate {
    id: string;
    name: string;
    subject: string;
    template: string;
    variables: string[];
  }
  
  export interface EmailLog {
    id: string;
    to: string;
    subject: string;
    template: string;
    status: 'sent' | 'failed' | 'pending';
    sentAt: Date;
    error?: string;
  }
  