import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';

import { UserService } from './user.service';
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';
import { TokenService } from './token.service';
import { MoreThanOrEqual } from 'typeorm';
import { OAuth2Client } from 'google-auth-library';

@Controller()
export class UserController {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private tokenService: TokenService,
  ) {}

  @Post('register')
  async register(@Body() body: any) {
    if (body.password !== body.confirm_password)
      throw new BadRequestException('Password do not match');

    return this.userService.save({
      first_name: body.first_name,
      last_name: body.last_name,
      address: body.address,
      password: await bcrypt.hash(body.password, 12),
      email: body.email,
    });
  }

  @Post('login')
  async login(
    @Body('email') email: string,
    @Body('password') password: string,
    @Res({ passthrough: true }) response: Response,
  ) {
    const user = await this.userService.findOne({ email });

    if (!user) throw new BadRequestException('Invalid crediential');

    if (!(await bcrypt.compare(password, user.password)))
      throw new UnauthorizedException('Invalid crediential');

    const accessToken = await this.jwtService.signAsync(
      { id: user.id },
      { expiresIn: '30s' },
    );

    const refreshToken = await this.jwtService.signAsync({ id: user.id });

    const expired_at = new Date();

    expired_at.setDate(expired_at.getDate() + 7);

    await this.tokenService.save({
      user_id: user.id,
      token: refreshToken,
      expired_at,
    });

    response.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    response.status(200);

    return { token: accessToken };
  }

  @Get('user')
  async user(@Req() request: Request) {
    try {
      const accessToken = request.headers.authorization.replace('Bearer ', '');

      const { id } = await this.jwtService.verifyAsync(accessToken);

      const { password, ...data } = await this.userService.findOne({ id });

      return data;
    } catch (error) {
      throw new UnauthorizedException();
    }
  }

  @Post('refresh')
  async refresh(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      const refreshToken = request.cookies['refresh_token'];

      const { id } = await this.jwtService.verifyAsync(refreshToken);

      const entityToken = await this.tokenService.findOne({
        user_id: id,
        expired_at: MoreThanOrEqual(new Date()),
      });

      if (!entityToken) throw new UnauthorizedException();

      const accessToken = await this.jwtService.signAsync(
        { id },
        { expiresIn: '30s' },
      );
      response.status(200);
      return { token: accessToken };
    } catch (error) {
      throw new UnauthorizedException();
    }
  }

  @Post('logout')
  async logout(
    @Res({ passthrough: true }) response: Response,
    @Req() request: Request,
  ) {
    const refreshToken = request.cookies['refresh_token'];
    const { user_id } = await this.tokenService.findOne({
      token: refreshToken,
    });

    await this.tokenService.delete({ user_id });
    response.clearCookie('refresh_token');

    return {
      message: 'success',
    };
  }

  @Post('google-auth')
  async google_auth(
    @Body('token') token: string,
    @Res({ passthrough: true }) response: Response,
  ) {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const client = new OAuth2Client(clientId);

    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: clientId,
    });

    const googleUser = ticket.getPayload();

    if (!googleUser) throw new UnauthorizedException();

    let user = await this.userService.findOne({ email: googleUser.email });

    if (!user) {
      user = await this.userService.save({
        first_name: googleUser.given_name,
        last_name: googleUser.family_name,
        email: googleUser.email,
        address: googleUser.locale,
        password: await bcrypt.hash(token, 12),
      });
    }

    const accessToken = await this.jwtService.signAsync(
      { id: user.id },
      { expiresIn: '30s' },
    );

    const refreshToken = await this.jwtService.signAsync({ id: user.id });

    const expired_at = new Date();

    expired_at.setDate(expired_at.getDate() + 7);

    await this.tokenService.save({
      user_id: user.id,
      token: refreshToken,
      expired_at,
    });

    response.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    response.status(200);

    return { token: accessToken };
  }
}
