package org.jscsi.target.storage;


import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.Files;


/**
 * Instances of this class can be used for persistent storage of data. They are backed by a {@link RandomAccessFile},
 * which will immediately write all changes in the data to hard-disk.
 * <p>
 * This class is <b>not</b> thread-safe.
 * 
 * @see java.io.RandomAccessFile
 * @author Andreas Ergenzinger
 */
public class RandomAccessStorageModule implements IStorageModule {

    //private static final Logger log = LogManager.getLogger(RandomAccessStorageModule.class);

    private static final int VIRTUAL_BLOCK_SIZE = 512;

    /**
     * The size of the medium in blocks.
     * 
     * @see #VIRTUAL_BLOCK_SIZE
     */
    protected final long sizeInBlocks;

    /**
     * The {@link RandomAccessFile} used for accessing the storage medium.
     */
    private final RandomAccessFile randomAccessFile;

    /**
     * 
     */
    private final FileChannel fileChannel;
    
    /**
     * Creates a new {@link RandomAccessStorageModule} backed by the specified file. If no such file exists, a
     * {@link FileNotFoundException} will be thrown.
     * 
     * @param sizeInBlocks blocksize for this module
     * @param file the path to the file serving as storage medium
     * @throws IOException 
     */
    public RandomAccessStorageModule (File file, long storageLength, boolean create) throws IOException {
        sizeInBlocks = storageLength / VIRTUAL_BLOCK_SIZE;
        
        File parent = file.getCanonicalFile().getParentFile();
        if (!parent.exists() && !parent.mkdirs()) {
        	throw new IOException("Unable to create directory: " + parent.getAbsolutePath());
        }

        if (create) {
        	Files.deleteIfExists(file.toPath());
        }
        
        randomAccessFile = new RandomAccessFile(file, "rwd");
		fileChannel = randomAccessFile.getChannel();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void read(byte[] bytes, long storageIndex) throws IOException {
        randomAccessFile.seek(storageIndex);
        randomAccessFile.read(bytes, 0, bytes.length);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void write(byte[] bytes, long storageIndex) throws IOException {
        randomAccessFile.seek(storageIndex);
        randomAccessFile.write(bytes, 0, bytes.length);
    }

    @Override
    public ByteBuffer getMappedBuffer(long startPosition, long length) throws IOException {
		return fileChannel.map(MapMode.READ_WRITE, startPosition, length);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final long getLastBlockIndex() {
        return sizeInBlocks - 1;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final int checkBounds(long logicalBlockAddress, int transferLengthInBlocks) {
    	if (logicalBlockAddress < 0 || logicalBlockAddress >= sizeInBlocks) {
    		return 1;
    	}
        if (transferLengthInBlocks < 0 || logicalBlockAddress + transferLengthInBlocks > sizeInBlocks) {
        	return 2;
        }

        return 0;
    }

    /**
     * Closes the backing {@link RandomAccessFile}.
     * 
     * @throws IOException if an I/O Error occurs
     */
    public final void close() throws IOException {
        randomAccessFile.close();
    }

    @Override
    public int getBlockSize() {
        return VIRTUAL_BLOCK_SIZE;
    }
}
