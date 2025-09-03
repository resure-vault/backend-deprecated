import express from 'express';
import cors from 'cors';
import { MailModule } from './routes/mail/mail.module';
import { DatabaseService } from './microservices/database';

const app = express();
const mailModule = new MailModule();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/mail', mailModule.getRouter());

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'resure-api'
  });
});

const PORT = process.env.PORT || 8080;

async function startServer() {
  try {
    const db = new DatabaseService();
    await db.initialize();
    
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
