import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { compare, hash } from 'bcryptjs';
import { Response } from 'express';
import { User } from 'src/users/schema/user.schema';
import { UsersService } from 'src/users/users.service';
import { TokenPayload } from './token-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService
  ){}

  async login(user: User, response: Response) {
    const expirateAccessToken = new Date();
    expirateAccessToken.setMilliseconds(
      expirateAccessToken.getTime() + 
      parseInt(this.configService.getOrThrow<string>('JWT_ACCESS_TOKEN_EXPIRATION_MS'))
    );

    const expirateRefreshToken = new Date();
    expirateRefreshToken.setMilliseconds(
      expirateRefreshToken.getTime() + 
      parseInt(this.configService.getOrThrow<string>('JWT_REFRESH_TOKEN_EXPIRATION_MS'))
    );
    
    const tokenPayload: TokenPayload = {
      userId: user._id.toHexString(),
    }

    const accessToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: `${this.configService.getOrThrow('JWT_ACCESS_TOKEN_EXPIRATION_MS')}ms`,
    })

    const refreshToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: `${this.configService.getOrThrow('JWT_REFRESH_TOKEN_EXPIRATION_MS')}ms`,
    })

    await this.usersService.updateUser(
      {_id: user._id},
      {$set: {refreshToken: await hash(refreshToken, 10)}}
    );

    response.cookie('Authentication', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      expires: expirateAccessToken,
    });

   response.cookie('Refresh', refreshToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      expires: expirateRefreshToken,
   });
  }

  async verifyUser(email: string, password: string) {
    try{
      const user =  await this.usersService.getUSer({
        email,
      });

      const authenticated = await compare(password, user.password);

      if(!authenticated) {
        throw new UnauthorizedException();
      }

      return user;
    }catch(err){
      throw new UnauthorizedException("Credentials are not valid"); 
    }
  }

  async verifyRefreshToken(refreshToken: string, userId: string) {
    try {
      const user = await this.usersService.getUSer({_id: userId});
      const authenticated = await compare(refreshToken, user.refreshToken);

      if(!authenticated)  {
        throw new UnauthorizedException();
      }

      return user;
    } catch(err) {
      throw new UnauthorizedException("Refresh token is not valid");
    }
  }
}
