import { ForbiddenException, Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import {JwtFromRequestFunction, Strategy } from "passport-jwt";
import { JWTPayload, JwtPayloadWithRefreshToken } from "../types";
import { Request } from "express";




export const CookieExtractor: JwtFromRequestFunction = (req:Request) =>{
    console.log(req.cookies);
    if(req  && req.cookies){
        return req.cookies['refreshToken']
    }
    return null
}




@Injectable()
export class RefreshTokenCookieStrategy extends PassportStrategy(
  Strategy,
  "refresh-jwt"
) {
  constructor() {
    super({
      jwtFromRequest: CookieExtractor,
      secretOrKey: process.env.REFRESH_TOKEN_KEY!,
      passReqToCallback: true,
    });
  }

  
  validate(req: Request, payload: JWTPayload): JwtPayloadWithRefreshToken{
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken){
        throw new ForbiddenException("Refresh Token Noto'g'ri")
    }
    return {...payload,refreshToken}
  }
}