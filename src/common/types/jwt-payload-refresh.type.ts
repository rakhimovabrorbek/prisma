import { JWTPayload } from "./jwt-payload.type";

export type JwtPayloadWithRefreshToken = JWTPayload & {refreshToken:string}