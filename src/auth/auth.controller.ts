import { Body, Controller, HttpCode, HttpStatus, Post, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../users/dto';
import { Response } from 'express';
import { SignInUserDto } from '../users/dto/sign-in.user.dto';
import { ResponseFields } from '../common/types';
import { RefreshTokenGuard } from '../common/guards/refresh-token.guard';
import { GetCurrentUser, GetCurrentUserId} from '../common/decorators';



@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("signup")
  async signUp(
    @Body() createUserDto: CreateUserDto,
    @Res({ passthrough: true }) res: Response
  ): Promise<ResponseFields> {
    return this.authService.signup(createUserDto, res);
  }

  @Post("signin")
  @HttpCode(200)
  async signIn(
    @Body() signInDto: SignInUserDto,
    @Res({ passthrough: true }) res: Response
  ): Promise<ResponseFields> {
    return this.authService.signInUser(signInDto, res);
  }

  @UseGuards(RefreshTokenGuard)
  @Post("refresh")
  @HttpCode(HttpStatus.OK)
  async refreshTokens(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser("refreshToken") refreshToken: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<ResponseFields> {
    return this.authService.refreshToken(userId, refreshToken, res);
  }

  @UseGuards(RefreshTokenGuard)
  @Post("signout")
  async signOut(
    @GetCurrentUserId() userId: number,
    @Res({ passthrough: true }) res: Response
  ): Promise<{ success: boolean }> {
    await this.authService.signOut(userId, res);
    return { success: true };
  }
}

