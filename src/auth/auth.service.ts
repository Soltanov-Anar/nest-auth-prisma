import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../../prisma/prisma.service';
import { AuthDTO } from './dto/auth.dto';
import { jwtSecret } from 'src/utils/constants';
import { User } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signup(authDTO: AuthDTO) {
    const { email, password } = authDTO;

    const foundUser: User = await this.prisma.user.findUnique({
      where: { email },
    });

    if (foundUser) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await this.hashPassword(password);

    await this.prisma.user.create({
      data: {
        email,
        hashedPassword,
      },
    });

    return {
      message: 'signup was succefull',
    };
  }

  async signin(authDTO: AuthDTO, response: Response) {
    const { email, password } = authDTO;

    const foundUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!foundUser) {
      throw new BadRequestException('Wrong credentials');
    }

    const { hashedPassword } = foundUser;

    const isMatch = await this.comparePasswords({
      password,
      hashedPassword,
    });

    if (!isMatch) {
      throw new BadRequestException('Wrong credentials');
    }

    const { id } = foundUser;

    const token = await this.signToken({ id, email });

    if (!token) {
      throw new ForbiddenException();
    }

    response.cookie('token', token);

    return response.send({
      message: 'Logged in successfully',
    });
  }

  async signout(response: Response) {
    response.clearCookie('token');

    return response.send({
      message: 'Logged out successfully',
    });
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;

    return await bcrypt.hash(password, saltOrRounds);
  }

  async comparePasswords(args: { password: string; hashedPassword: string }) {
    const { password, hashedPassword } = args;
    return await bcrypt.compare(password, hashedPassword);
  }

  async signToken(payload: { id: string; email: string }) {
    return this.jwtService.signAsync(payload, {
      secret: jwtSecret,
    });
  }
}
