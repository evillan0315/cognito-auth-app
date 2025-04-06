import { Controller, Get, Render } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @Render('index') // Render the "index.hbs" file
  getIndex() {
    return { message: 'Welcome to the NestJS API Server!' }; // Data to pass to the template
  }
  @Get('terminal')
  @Render('terminal') // Render the "index.hbs" file
  getTerminal() {
    return { message: 'Welcome to web terminal!' }; // Data to pass to the template
  }
}
