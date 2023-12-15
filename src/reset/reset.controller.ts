import {
  BadRequestException,
  Body,
  Controller,
  NotFoundException,
  Post,
} from '@nestjs/common';
import { ResetService } from './reset.service';
import { MailerService } from '@nestjs-modules/mailer';
import { UserService } from '../user/user.service';
import * as bcrypt from 'bcrypt';

@Controller()
export class ResetController {
  constructor(
    private resetService: ResetService,
    private mailerService: MailerService,
    private userService: UserService,
  ) {}

  @Post('forget')
  async forget(@Body('email') email: string) {
    const token = Math.random().toString(20).substring(2, 12);

    await this.resetService.save({
      email,
      token,
    });

    const url = `http://localhost:5173/reset/${token}`;

    await this.mailerService.sendMail({
      to: email,
      subject: 'Reset your password',
      html: `Click <a href="${url}"> here </a> to reset your password!`,
    });

    return {
      message: 'check your mail',
    };
  }

  @Post('reset')
  async reset(
    @Body('token') token: string,
    @Body('password') password: string,
    @Body('confirm_password') confirm_password: string,
  ) {
    if (password !== confirm_password) {
      throw new BadRequestException('Password do not match!');
    }
    if (!token) throw new BadRequestException('Token is not provided');
    console.log(token);
    const reset = await this.resetService.findOne({ token });

    console.log(reset);

    const user = await this.userService.findOne({ email: reset.email });

    if (!user) {
      throw new NotFoundException('User is not found');
    }

    await this.userService.update(user.id, {
      password: await bcrypt.hash(password, 12),
    });

    return {
      message: 'success',
    };
  }
}
