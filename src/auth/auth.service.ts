import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import * as argon from "argon2"
import { AuthDto } from "./dto";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()

export class AuthService {
    constructor(
        private jwt: JwtService,
        private config: ConfigService,
        private prisma: PrismaService,
    ) {}

    async signup(dto: AuthDto) {
        //hash the password string with argon
        const hash = await argon.hash(dto.password)

        try {
            //create user data in the database
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    password:  hash
                }
            })
            
            return this.signToken(user.id, user.email)
        } catch(error) {
            if(error instanceof PrismaClientKnownRequestError) {
                if(error.code === "P2002") {
                    throw new ForbiddenException("Credentials taken.")
                }
            }

            throw error
        }
    }

    async signin(dto: AuthDto) {
        //find the user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email
            }
        })

        if(!user)
            throw new ForbiddenException("Credentials incorrect.")

        //compare password
        const passwordMatches = await argon.verify(user.password, dto.password)

        if(!passwordMatches)
            throw new ForbiddenException("Credentials incorrect.")

        return this.signToken(user.id, user.email)
    }

    async signToken(userId: number, email: string): Promise<{access_token: string}> {
        const secret = this.config.get('JWT_SECRET')
        const payload = {
            sub: userId,
            email
        }

        const token = await this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: secret
        })

        return {
            access_token: token
        }
    }
}