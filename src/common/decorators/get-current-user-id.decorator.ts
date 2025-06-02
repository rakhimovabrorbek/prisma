import { createParamDecorator, ExecutionContext, ForbiddenException } from "@nestjs/common";
import { JWTPayload } from "../types";

export const GetCurrentUserId = createParamDecorator(
  (_: undefined, context: ExecutionContext): number => {
    const request = context.switchToHttp().getRequest(); 
    const user = request.user as JWTPayload
    if(!user){
        throw new ForbiddenException("Token noto'gri")
    }
    console.log("user",user);
   
    return user.id
  }
);
