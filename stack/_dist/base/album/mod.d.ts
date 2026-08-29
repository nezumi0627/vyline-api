import type { BaseClient } from "../mod.ts";
export declare const ALBUM_CHANNEL_ID = "1375220249";
export interface AlbumInfo {
    albumId: string;
    chatId: string;
    title?: string;
    photoCount?: number;
    createTime?: number;
    updateTime?: number;
}
export interface AlbumPhoto {
    id?: string | number;
    photoId?: string | number;
    oid?: string;
    obsResourceId?: {
        oid?: string;
        svc?: string;
        sid?: string;
    };
    resourceType?: string;
    width?: number;
    height?: number;
}
export type AlbumsResponse = {
    code?: number;
    message?: string;
    result?: {
        albums: AlbumInfo[];
        cursor?: string;
        nextCursor?: string;
        hasMore?: boolean;
    };
};
export type AlbumPhotosResponse = {
    code?: number;
    message?: string;
    result?: {
        photos: AlbumPhoto[];
        nextCursor?: string;
    };
};
export type AlbumPhotoCreateInput = {
    obsResourceId: {
        oid: string;
        sid?: string;
        svc?: string;
    };
    width: number;
    height: number;
    shotTime?: number;
    resourceType?: "IMAGE" | "VIDEO" | string;
};
export declare function buildAlbumUrl(endpoint: string, path: string, query?: Record<string, string | number | undefined>): string;
/** LINE Album JSON REST client (iOS 26.12.1 observed API). */
export declare class Album {
    private readonly client;
    private token?;
    constructor(client: BaseClient);
    private channelToken;
    private json;
    list(options: {
        chatId: string;
        cursor?: string;
        orderBy?: string;
        include?: string;
    }): Promise<AlbumsResponse>;
    preview(options: {
        chatId: string;
        pageSize?: number;
        thumbnailCount?: number;
        viewType?: string;
    }): Promise<{
        code?: number;
        message?: string;
    }>;
    create(options: {
        chatId: string;
        title: string;
        modifyDuplicateTitle?: boolean;
    }): Promise<{
        code?: number;
        message?: string;
    }>;
    update(options: {
        chatId: string;
        albumId: string | number;
        title: string;
    }): Promise<{
        code?: number;
        message?: string;
    }>;
    delete(options: {
        chatId: string;
        albumId: string | number;
    }): Promise<{
        code?: number;
        message?: string;
    }>;
    share(options: {
        chatId: string;
        albumId: string | number;
    }): Promise<{
        code?: number;
        message?: string;
    }>;
    photos(options: {
        chatId: string;
        albumId: string | number;
        cursor?: string;
        pageSize?: number;
        orderBy?: string;
        include?: string;
        filterType?: string;
        targetUser?: string;
    }): Promise<AlbumPhotosResponse>;
    addPhotos(options: {
        chatId: string;
        albumId: string | number;
        photos: AlbumPhotoCreateInput[];
    }): Promise<{
        code?: number;
        message?: string;
    }>;
    deletePhotos(options: {
        chatId: string;
        albumId: string | number;
        photoIds: Array<string | number>;
    }): Promise<{
        code?: number;
        message?: string;
    }>;
    upload(options: {
        chatId: string;
        albumId: string | number;
        oid: string;
        data: Blob;
    }): Promise<{
        oid: string;
    }>;
    download(options: {
        chatId: string;
        albumId: string | number;
        oid: string;
        mediaType?: "image" | "video";
    }): Promise<Response>;
}
