import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { JWTPayload } from "../types";
import { Request } from "express";

@Injectable()
export class AccessTokenStrategy extends PassportStrategy(
    Strategy,
    "access-jwt"
){
    constructor(){
        super({jwtFromRequest:ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: process.env.ACCESS_TOKEN_KEY!,
            passReqToCallback:true
        })
    }

    validate(req:Request,payload: JWTPayload): JWTPayload {
        console.log("request",req);
        console.log("payload",payload);
        return payload
    }

}