import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class AuthDTO {
  @IsNotEmpty()
  @IsEmail()
  @IsString()
  public readonly email: string;

  @IsNotEmpty()
  @IsString()
  @Length(4, 25, { message: 'Password has to be at between 4 and 25 chars' })
  public readonly password: string;
}
