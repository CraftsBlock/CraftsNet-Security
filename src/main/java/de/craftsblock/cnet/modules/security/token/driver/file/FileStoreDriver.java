package de.craftsblock.cnet.modules.security.token.driver.file;

import de.craftsblock.cnet.modules.security.token.driver.WrappedStoreDriver;

import java.nio.file.Path;

public final class FileStoreDriver extends WrappedStoreDriver<FileGroupStoreDriver, FileTokenStoreDriver> {

    FileStoreDriver(FileGroupStoreDriver groupStoreDriver, FileTokenStoreDriver tokenStoreDriver) {
        super(groupStoreDriver, tokenStoreDriver);
    }

    @Override
    public FileGroupStoreDriver getGroupStoreDriver() {
        return super.getGroupStoreDriver();
    }

    @Override
    public FileTokenStoreDriver getTokenStoreDriver() {
        return super.getTokenStoreDriver();
    }

    public static FileStoreDriver create(Path groupsFile, Path tokensFile) {
        return new FileStoreDriver(
                new FileGroupStoreDriver(groupsFile),
                new FileTokenStoreDriver(tokensFile)
        );
    }

}
