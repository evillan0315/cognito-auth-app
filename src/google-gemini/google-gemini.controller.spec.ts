import { Test, TestingModule } from '@nestjs/testing';
import { GoogleGeminiController } from './google-gemini.controller';

describe('GoogleGeminiController', () => {
  let controller: GoogleGeminiController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [GoogleGeminiController],
    }).compile();

    controller = module.get<GoogleGeminiController>(GoogleGeminiController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
