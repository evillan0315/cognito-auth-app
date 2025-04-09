import { Test, TestingModule } from '@nestjs/testing';
import { GoogleGeminiService } from './google-gemini.service';

describe('GoogleGeminiService', () => {
  let service: GoogleGeminiService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [GoogleGeminiService],
    }).compile();

    service = module.get<GoogleGeminiService>(GoogleGeminiService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
