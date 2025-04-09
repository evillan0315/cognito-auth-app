import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';
import * as dotenv from 'dotenv';
import * as cookieParser from 'cookie-parser';
import { NestExpressApplication } from '@nestjs/platform-express';
import * as path from 'path';
import * as express from 'express';
import { join } from 'path';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:4173',
    'http://localhost:5000',
    'https://board-api.duckdns.org',
    'https://board-dynamodb.duckdns.org',
  ];

  app.use(cookieParser());
  app.enableCors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.error(`Blocked by CORS: ${origin}`); // Debugging
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });

  // Serve public assets (SolidJS build output)
  app.use('/', express.static(path.join(__dirname, '..', 'public/js')));

  // Serve PostgreSQL module documentation
  app.use(
    '/docs/postgres',
    express.static(join(__dirname, '..', 'src/database/postgres/docs')),
  );

  // Set Handlebars as the view engine
  app.setViewEngine('hbs');

  // Set the base directory for views
  app.setBaseViewsDir(path.join(__dirname, '..', 'views'));
  // Swagger Configuration
  const swaggerConfig = new DocumentBuilder()
    .setTitle('Server API')
    .setDescription('API Documentation')
    .setVersion('1.0')
    .addTag('Auth')
    .addBearerAuth() // Enable Authorization Header
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api', app, document); // Swagger UI at /api/docs

  // Graceful shutdown setup
  app.enableShutdownHooks(); // Handle graceful shutdown

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
