import { BadRequestException, ConflictException, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from '../users/dto';
import * as bcrypt from "bcrypt";
import { User } from '../../generated/prisma';
import { Response } from 'express';
import { SignInUserDto } from '../users/dto/sign-in.user.dto';
import { JWTPayload, Tokens } from '../common/types';


@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService
  ) {}

  async generateTokenforUser(user: User): Promise<Tokens>{
    const payload: JWTPayload = {
      id: user.id,
      is_active: user.is_active,
      email: user.email
    };
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(payload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);
    return { accessToken, refreshToken };
  }

  async signup(createUserDto: CreateUserDto, res: Response) {
    const { email } = createUserDto;
    const candidate = await this.prismaService.user.findUnique({
      where: { email },
    });
    if (candidate) {
      throw new ConflictException("Email already exists");
    }
    const { password, confirm_password, ...otherDto } = createUserDto;
    if (password != confirm_password) {
      throw new BadRequestException("Password do not match");
    }
    const hashed_password = await bcrypt.hash(password, 7);
    const user = await this.prismaService.user.create({
      data: { ...otherDto, hashed_password },
    });
    const tokens:Tokens = await this.generateTokenforUser(user);
    const hashed_refresh_token = await bcrypt.hash(tokens.refreshToken, 7);
    await this.updateRefreshToken(user.id, hashed_refresh_token);
    res.cookie("refreshToken", tokens.refreshToken, {
      maxAge: Number(process.env.COOKIE_TIME),
      httpOnly: true,
    });
    return {
      message: `New User Signed-up`,
      accessToken: tokens.accessToken,
      id:user.id
    };
  }

  async updateRefreshToken(userId: number, refreshToken: string) {
    await this.prismaService.user.update({
      where: { id: userId },
      data: {
        hashed_refresh_token: refreshToken,
      },
    });
  }

  async signInUser(signInDto: SignInUserDto, res: Response) {
     const user = await this.prismaService.user.findUnique({
       where: {email:signInDto.email},
     });
     if (!user) {
       throw new BadRequestException("Email or password is wrong");
     }
    const isValid = await bcrypt.compare(
      signInDto.password,
      user.hashed_password
    );
    if (!isValid) {
      throw new BadRequestException("Email yoki Password Noto'g'ri");
    }
    const { accessToken, refreshToken } =
      await this.generateTokenforUser(user);
    res.cookie("refreshToken", refreshToken, {
      maxAge: Number(process.env.COOKIE_TIME),
      httpOnly: true,
    });
    const hashed_refresh_token = await bcrypt.hash(refreshToken, 7);
    user.hashed_refresh_token = hashed_refresh_token;
    await this.prismaService.user.update({
      where: { id: user.id },
      data: { hashed_refresh_token },
    });
    return { message: "Tizimga xush kelibsiz", id: user.id, accessToken };
  }

  async refreshToken(userId:number,refreshToken:string,res:Response){
    const user = await this.prismaService.user.findUnique({where:{id:userId}})
    if(!user || !user.hashed_refresh_token){
      throw new ForbiddenException("Access Denied")
    }
    const rtMatches = await bcrypt.compare(refreshToken,user.hashed_refresh_token)
    if(!rtMatches){
      throw new ForbiddenException("Access Denied")
    }
    const tokens: Tokens = await this.generateTokenforUser(user)
    const hashed_refresh_token = await bcrypt.hash(tokens.refreshToken,7)
    await this.updateRefreshToken(user.id,hashed_refresh_token)
    res.cookie("refreshToken", tokens.refreshToken,{
      maxAge: +process.env.COOKIE_TIME!,
      httpOnly:true
    })
    return {
      message:"Tokens are updated",
      id:user.id,
      accessToken:tokens.accessToken
    }
  }

  async signOut(userId:number,res:  Response){
  const user = await this.prismaService.user.findUnique({where:{id:userId}})
  if(!user || !user.hashed_refresh_token){
    throw new ForbiddenException("Access Denied")
  }
  res.clearCookie("refreshToken");
  await this.prismaService.user.update({
    where:{id:userId},
    data:{hashed_refresh_token:null}
  })
    return {message:"User signed out successfully"}
  }

}