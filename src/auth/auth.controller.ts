import { Body, Controller, Get, Post, Res } from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';
import { AuthDTO } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() authDTO: AuthDTO) {
    return this.authService.signup(authDTO);
  }

  @Post('signin')
  signin(@Body() authDTO: AuthDTO, @Res() response: Response) {
    return this.authService.signin(authDTO, response);
  }

  @Get('signout')
  signout(@Res() response: Response) {
    return this.authService.signout(response);
  }
}
