import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto, UpdateUserDto } from './dto';
import * as bcrypt from 'bcrypt'

@Injectable()
export class UsersService {
  constructor(private readonly prismaService: PrismaService){}


  async create(createUserDto: CreateUserDto) {
    const {password,confirm_password,...otherDto} = createUserDto
    if(password!=confirm_password){
      throw new BadRequestException("password do not match")
    }
    const hashed_password = await bcrypt.hash(password,7)
    return this.prismaService.user.create({data:{...otherDto,hashed_password}})
  }


  findAll() {
    return this.prismaService.user.findMany()  }

  findOne(id: number) {
    return this.prismaService.user.findUnique({where:{id}})
  }
   
  update(id: number, updateUserDto: UpdateUserDto) {
    return this.prismaService.user.update({where:{id},data:updateUserDto})
  }

  remove(id: number) {
   return this.prismaService.user.delete({where:{id}})
  }
}
