import { ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from './../../prisma/prisma.service';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async getMyUser(id: string, request: Request & { user: { id: string; email: string } }) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        createdAt: true,
        updateAt: true,
      },
    });

    if (!user) {
      throw new NotFoundException();
    }

    const decodedUser = request.user as { id: string; email: string };

    if (user.id !== decodedUser.id) {
      throw new ForbiddenException();
    }

    return { user };
  }

  async getUsers() {
    const users = await this.prisma.user.findMany({
      select: { id: true, email: true },
    });

    return { users };
  }
}
