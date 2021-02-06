from tensorflow import keras, saved_model, summary
from data import get_train_data
from models import get_cnn_model
from os import path, getcwd, chdir
from datetime import datetime
from utils import load_json, get_script_directory
import math
import itertools

def get_tensorboard_callback():
    logfile = datetime.now().strftime("%Y%m%d-%H%M%S")
    logdir = path.join("logs", "fit", logfile)

    file_writer = summary.create_file_writer(logdir)
    file_writer.set_as_default()

    tensorboard_callback = keras.callbacks.TensorBoard(
        histogram_freq=1,
        log_dir=logdir)

    return tensorboard_callback

def main():
    
    script_directory = get_script_directory()
    chdir(script_directory)

    image_width = 150
    image_height = 150
    channels_count = 3
    epochs = 50
    dataset_length = 75
    batch_size = 15
    dataset = load_json("processed_data.json")
    dataset = dataset[:dataset_length]
    number_of_categories = len(dataset)
    steps_per_epoch = math.ceil(dataset_length / batch_size)

    input_shape = (image_width, image_height, channels_count)
    model = get_cnn_model(input_shape, number_of_categories)
    train_data = get_train_data(
        dataset,
        image_width,
        image_height,
        channels_count,
        batch_size)

    model.compile(
        optimizer=keras.optimizers.Adam(),
        loss=keras.losses.SparseCategoricalCrossentropy(from_logits=True),
        metrics=["accuracy"]
    )

    model.summary()

    checkpoint_path = "training_checkpoint/cp-{epoch:04d}.ckpt"
    model.save_weights(checkpoint_path.format(epoch=0))

    cp_callback = keras.callbacks.ModelCheckpoint(
        filepath=checkpoint_path, 
        verbose=1, 
        save_weights_only=True,
        save_freq=5 * batch_size)

    tensorboard_callback = get_tensorboard_callback()

    model.fit(
        train_data,
        batch_size=batch_size,
        steps_per_epoch=steps_per_epoch,
        epochs=epochs,
        callbacks=[cp_callback, tensorboard_callback])

    model_name = "cnn_32_64_128"
    model.save("saved_model/{}".format(model_name))

if __name__ == '__main__':
    main()