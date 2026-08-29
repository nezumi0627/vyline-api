import type { BaseClient } from "../mod.ts";
import type { LooseType } from "@vyline/loose-types";
export type TimelineResponse<T = LooseType> = {
    code: number;
    message: string;
    result: T;
};
export declare class Timeline {
    #private;
    protected timelineToken: string | undefined;
    timelineHeaders: Record<string, string | undefined>;
    client: BaseClient;
    constructor(client: BaseClient);
    initTimeline(): Promise<void>;
    createPost(options: {
        homeId: string;
        text?: string;
        sharedPostId?: string;
        textSizeMode?: "AUTO" | "NORMAL";
        backgroundColor?: string;
        textAnimation?: "NONE" | "SLIDE" | "ZOOM" | "BUZZ" | "BOUNCE" | "BLINK";
        readPermissionType?: "ALL" | "FRIEND" | "GROUP" | "EVENT" | "NONE";
        readPermissionGids?: string[];
        holdingTime?: number;
        stickerIds?: string[];
        stickerPackageIds?: string[];
        locationLatitudes?: number[];
        locationLongitudes?: number[];
        locationNames?: string[];
        mediaObjectIds?: string[];
        mediaObjectTypes?: string[];
        sourceType?: string;
        contents?: LooseType;
        postInfo?: LooseType;
    }): Promise<TimelineResponse>;
    deletePost(options: {
        homeId: string;
        postId: string;
    }): Promise<TimelineResponse>;
    getPost(options: {
        homeId: string;
        postId: string;
    }): Promise<TimelineResponse>;
    listPost(options: {
        homeId: string;
        postId?: string;
        updatedTime?: number;
        sourceType?: string;
        postLimit?: number;
        showVideoPostsOnly?: boolean;
    }): Promise<TimelineResponse>;
    updatePost(options: {
        homeId: string;
        postId: string;
        text?: string;
        sharedPostId?: string;
        textSizeMode?: "AUTO" | "NORMAL";
        backgroundColor?: string;
        textAnimation?: "NONE" | "SLIDE" | "ZOOM" | "BUZZ" | "BOUNCE" | "BLINK";
        holdingTime?: number;
        stickerIds?: string[];
        stickerPackageIds?: string[];
        locationLatitudes?: number[];
        locationLongitudes?: number[];
        locationNames?: string[];
        mediaObjectIds?: string[];
        mediaObjectTypes?: string[];
        contents?: LooseType;
    }): Promise<TimelineResponse>;
    likePost(options: {
        contentId: string;
        homeId: string;
        likeType?: "1003" | "1001" | "1002" | "1004" | "1006" | "1005";
        sourceType?: string;
    }): Promise<TimelineResponse>;
    unlikePost(options: {
        contentId: string;
        homeId: string;
        sourceType?: string;
    }): Promise<TimelineResponse>;
    getLike(options: {
        contentId: string;
        homeId: string;
    }): Promise<TimelineResponse>;
    listLikes(options: {
        contentId: string;
        homeId: string;
        sourceType?: string;
    }): Promise<TimelineResponse>;
    createComment(options: {
        contentId: string;
        commentText: string;
        homeId: string;
        sourceType?: string;
        contentsList?: LooseType[];
    }): Promise<TimelineResponse>;
    sharePost(options: {
        postId: string;
        homeId: string;
    }): Promise<TimelineResponse>;
    getGroupHomeUpdates(revision: number): Promise<TimelineResponse>;
    /** Upload Note post media using the current iOS/iPad OBS path. */
    uploadNoteMedia(type: "image" | "video", data: Blob): Promise<{
        objId: string;
        objHash: string;
    }>;
    /**
     * Uploads an image into the myhome comment OBS space (`myhome/cmt`) for use in
     * a Note comment's `contentsList` media entry (`{ categoryId: "media", extData:
     * { objectId, type: "PHOTO", obsNamespace: "cmt", serviceName: "myhome", … } }`).
     *
     * Unlike {@link uploadNoteMedia}, the server assigns the object id here, so the
     * returned `objId` comes from the response `x-obs-oid` — reusing a client-chosen
     * id would leave the comment referencing a non-existent object (renders broken).
     * Note comments accept images only (video comments are not supported by LINE).
     */
    uploadNoteCommentImage(data: Blob): Promise<{
        objId: string;
        objHash: string;
    }>;
}
