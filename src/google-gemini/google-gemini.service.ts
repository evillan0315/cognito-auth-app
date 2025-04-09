import { Injectable } from '@nestjs/common';
import axios from 'axios';
import { GeminiDto } from './dto/gemini.dto';
import { PrismaService } from '../prisma/prisma.service';
import { Message, Chat, ApiUsage } from '@prisma/client';
import fs from 'fs';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { ApiTags } from '@nestjs/swagger';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const idirname = dirname(__filename);

import * as dotenv from 'dotenv';

dotenv.config();
@ApiTags('Google Gemini')
@Injectable()
export class GoogleGeminiService {
  private readonly apiKey = process.env.GOOGLE_GEMINI_API_KEY;
  private readonly googleGeminiApiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${this.apiKey}`;

  constructor(private prisma: PrismaService) {}
  // Method to call the Gemini API
  async generateContent(geminiDto: GeminiDto): Promise<any> {
    try {
      const response = await axios.post(this.googleGeminiApiUrl, geminiDto, {
        headers: {
          'Content-Type': 'application/json',
        },
      });
      return response.data; // Return the API response
    } catch (error) {
      console.error(
        'Error with Google Gemini API:',
        error.response?.data || error.message,
      );
      throw new Error('Failed to get response from Google Gemini');
    }
  }

  async processInputAndSaveToDb(
    userId: string,
    question: string,
    chatId: string,
  ): Promise<any> {
    try {
      const genAI = new GoogleGenerativeAI(`${this.apiKey}`);
      const model = genAI.getGenerativeModel({
        model: 'gemini-1.5-flash',
      });

      // Make the request to Google Gemini API
      /* const response = await axios.post(
      this.googleGeminiApiUrl,
      {
        contents: [
          {
            parts: [
              {
                text: question,
              },
            ],
          },
        ],
      },
      {
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );*/
      const countResult = await model.countTokens(question);
      const generateResult = await model.generateContent(question);
      const processedContent = generateResult.response.text(); // Handle the response data
      const user = await this.prisma.user.findUnique({
        where: {
          email: userId || 'ed9318d8-ac06-4925-b807-38fe8afeb1fa', // Check for the uniqueness of the chatId
        },
      });
      const existingChat = await this.prisma.chat.findUnique({
        where: {
          id: chatId || 'ed9318d8-ac06-4925-b807-38fe8afeb1fa', // Check for the uniqueness of the chatId
        },
      });

      let message: Message | null = null; // Declare message as Message | null
      let aiMessage: Message | null = null; // Declare aiMessage as Message | null
      let apiUsage: ApiUsage | null = null;
      let chat: Chat | null = null;

      if (existingChat) {
        // Save the processed content into the database
        message = await this.prisma.message.create({
          data: {
            chatId,
            content: question,
            sender: 'USER',
          },
        });

        // Save the response from Gemini as a message from the AI
        aiMessage = await this.prisma.message.create({
          data: {
            chatId,
            content: processedContent,
            sender: 'AI',
          },
        });

        // Save API usage information
        apiUsage = await this.prisma.apiUsage.create({
          data: {
            messageId: aiMessage?.id,
            inputTokens:
              generateResult?.response?.usageMetadata?.candidatesTokenCount, // Example data from the API
            outputTokens:
              generateResult?.response?.usageMetadata?.totalTokenCount, // Example data from the API
            cost: countResult.totalTokens, // Example cost from the API
          },
        });
      } else {
        // If no existing chat, create a new chat
        chat = await this.prisma.chat.create({
          data: {
            userId: user?.id || '684b136d-62c0-49ba-b514-a2fedf19a162',
          },
        });
        if (chat?.id) {
          chatId = chat.id;
          message = await this.prisma.message.create({
            data: {
              chatId,
              content: question,
              sender: 'USER',
            },
          });

          // Save the response from Gemini as a message from the AI
          aiMessage = await this.prisma.message.create({
            data: {
              chatId,
              content: processedContent,
              sender: 'AI',
            },
          });

          // Save API usage information
          apiUsage = await this.prisma.apiUsage.create({
            data: {
              messageId: aiMessage?.id,
              inputTokens:
                generateResult?.response?.usageMetadata?.candidatesTokenCount, // Example data from the API
              outputTokens:
                generateResult?.response?.usageMetadata?.totalTokenCount, // Example data from the API
              cost: countResult.totalTokens, // Example cost from the API
            },
          });
        }
      }

      return {
        message: message ?? null,
        aiMessage: aiMessage ?? null,
        apiUsage: apiUsage ?? null,
        chat: chat ?? null,
      };
    } catch (error) {
      console.error('Error with Google Gemini API:', error.message);
      throw new Error('Failed to get response from Google Gemini');
    }
  }
}
