from tensorflow import keras, saved_model
from tensorflow.keras import Sequential
from tensorflow.keras.layers import Dropout, Conv2D, MaxPooling2D, Flatten, Dense, BatchNormalization, Activation

def get_cnn_model(hparams, HP_NUM_UNITS, HP_DROPOUT, HP_OPTIMIZER, input_shape, number_of_categories):
    pool_size = (2, 2)

    return Sequential([
        Conv2D(
            32,
            kernel_size=(5, 5),
            padding="same",
            activation="relu",
            input_shape=input_shape),
        MaxPooling2D(pool_size),
        Dropout(hparams[HP_DROPOUT]),
        Conv2D(64,
            kernel_size=(5, 5),
            padding="same",
            activation='relu'),
        MaxPooling2D(pool_size),
        Dropout(hparams[HP_DROPOUT]),
        Conv2D(128,
            kernel_size=(5, 5),
            padding="same",
            activation='relu'),
        MaxPooling2D(pool_size),
        Dropout(hparams[HP_DROPOUT]),
        Flatten(),
        Dense(hparams[HP_NUM_UNITS]),
        BatchNormalization(),
        Activation("relu"),
        Dense(hparams[HP_NUM_UNITS]),
        BatchNormalization(),
        Activation("relu"),
        Dense(number_of_categories),
        BatchNormalization(),
        Activation("softmax")
    ])

       
