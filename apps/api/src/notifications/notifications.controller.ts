import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
} from '@nestjs/common';
import {
  ApiCookieAuth,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type {
  NotificationPage,
  NotificationUnreadCount,
} from '@infraward/shared-types';
import { PageQueryDto } from '../assets/assets.dto.js';
import { CurrentUser } from '../auth/current-user.decorator.js';
import type { AuthenticatedUser } from '../auth/authenticated-user.js';
import {
  NotificationPageDto,
  NotificationUnreadCountDto,
} from '../inventory/inventory.dto.js';
import { NotificationsService } from './notifications.service.js';

/** Avisos de la reconciliación (DESIGN §10): altas, desaparecidos, retirados y fallos. */
@ApiTags('notifications')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('notifications')
export class NotificationsController {
  constructor(private readonly notifications: NotificationsService) {}

  /** Las más recientes primero; `unread` según el último «Marcar como leídas» del usuario. */
  @Get()
  @ApiOkResponse({ type: NotificationPageDto })
  list(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: PageQueryDto,
  ): Promise<NotificationPage> {
    return this.notifications.list(
      user.id,
      query.limit ?? 20,
      query.offset ?? 0,
    );
  }

  @Get('unread-count')
  @ApiOkResponse({ type: NotificationUnreadCountDto })
  unreadCount(
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<NotificationUnreadCount> {
    return this.notifications.unreadCount(user.id);
  }

  @Post('seen')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: NotificationUnreadCountDto })
  markSeen(
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<NotificationUnreadCount> {
    return this.notifications.markSeen(user.id);
  }
}
