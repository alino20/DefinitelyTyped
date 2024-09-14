declare module '@parse/fs-files-adapter' {

    type EncryptionKey = string | number | boolean | null
  
    function FileSystemAdapter(options?: {
      encryptionKey?: EncryptionKey,
      filesSubDirectory?: string
    }): FileSystemAdapterInstance;
  
    interface FileSystemAdapterInstance {
      createFile(filename: string, data: any): Promise<any>;
      deleteFile(filename: string): Promise<void>;
      getFileData(filename: string): Promise<any>;
      rotateEncryptionKey(options: {
        oldKey: EncryptionKey,
        fileNames: string[]
      }): { rotated: string[], notRotated: string[] };
      getFileLocation(config: { mount: string, applicationId: string }, filename: string): string
    }
  }