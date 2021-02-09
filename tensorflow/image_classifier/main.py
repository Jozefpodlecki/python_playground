from tensorflow import keras, saved_model, summary
from tensorboard.plugins.hparams import api as hp
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
        write_images=True,
        log_dir=logdir)

    return tensorboard_callback

def train_model(hparams):
    with summary.create_file_writer('logs/hparam_tuning').as_default():
        hp.hparams_config(
            hparams=[HP_NUM_UNITS, HP_DROPOUT, HP_OPTIMIZER],
            metrics=[hp.Metric(METRIC_ACCURACY, display_name='Accuracy')],
        )

    model.compile(
        optimizer=optimizer=hparams[HP_OPTIMIZER],
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
        callbacks=[
            cp_callback,
            tensorboard_callback,
            hp.KerasCallback(logdir, hparams)])

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
    
    train_data = get_train_data(
        dataset,
        image_width,
        image_height,
        channels_count,
        batch_size)

    HP_NUM_UNITS = hp.HParam('num_units', hp.Discrete([128, 256]))
    HP_DROPOUT = hp.HParam('dropout', hp.RealInterval(0.1, 0.2))
    HP_OPTIMIZER = hp.HParam('optimizer', hp.Discrete(['adam', 'sgd']))

    model = get_cnn_model(hparams, input_shape, number_of_categories)
    train_model(hparams, HP_NUM_UNITS, HP_DROPOUT, HP_OPTIMIZER, model)

    model_name = "cnn_32_64_128"
    model.save("saved_model/{}".format(model_name))

if __name__ == '__main__':
    main()