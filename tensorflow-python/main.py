from tensorflow import keras, saved_model
from data import get_train_data
from models import get_cnn_model
from os import path, getcwd, chdir
from datetime import datetime
from utils import load_json, get_script_directory
import itertools

def get_tensorboard_callback():
    logfile = datetime.now().strftime("%Y%m%d-%H%M%S")
    logdir = path.join("logs", "fit", logfile)
    tensorboard_callback = keras.callbacks.TensorBoard(
        log_dir=logdir,
        histogram_freq=1,
        write_images=True,
        write_graph=True)

    return tensorboard_callback

def main():
    
    script_directory = get_script_directory()
    chdir(script_directory)

    image_width = 150
    image_height = 150
    channels_count = 3
    data = load_json("processed_data.json")
    data = data[:25]
    number_of_categories = len(data)
    batch_size = 5

    input_shape = (image_width, image_height, channels_count)
    model = get_cnn_model(input_shape, number_of_categories)
    train_data = get_train_data(
        data,
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

    tensorboard_callback = get_tensorboard_callback()

    model.fit(
        train_data,
        batch_size=batch_size,
        steps_per_epoch=50,
        epochs=10,
        callbacks=[tensorboard_callback])

if __name__ == '__main__':
    main()