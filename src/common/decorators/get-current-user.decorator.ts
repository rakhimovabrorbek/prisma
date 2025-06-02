import { createParamDecorator, ExecutionContext, ForbiddenException } from "@nestjs/common";
import { JWTPayload, JwtPayloadWithRefreshToken } from "../types";


export const GetCurrentUser = createParamDecorator(
  (data: keyof JwtPayloadWithRefreshToken, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest();
    const user = request.user as JWTPayload;
    console.log(user);
    console.log(data);
    if (!user) {
      throw new ForbiddenException("Token noto'gri");
    }
    if(!data){
        return user
    }
    return user[data]
  }
);
