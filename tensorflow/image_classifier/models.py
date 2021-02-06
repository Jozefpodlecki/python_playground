from tensorflow import keras, saved_model
from tensorflow.keras import Sequential
from tensorflow.keras.layers import Dropout, Conv2D, MaxPooling2D, Flatten, Dense, BatchNormalization, Activation

def get_cnn_model(input_shape, number_of_categories):
    pool_size = (2, 2)

    return Sequential([
        Conv2D(
            32,
            kernel_size=(5, 5),
            padding="same",
            activation="relu",
            input_shape=input_shape),
        MaxPooling2D(pool_size),
        Dropout(0.25),
        Conv2D(64,
            kernel_size=(5, 5),
            padding="same",
            activation='relu'),
        MaxPooling2D(pool_size),
        Dropout(0.25),
        Conv2D(128,
            kernel_size=(3, 3),
            padding="same",
            activation='relu'),
        MaxPooling2D(pool_size),
        Dropout(0.25),
        Flatten(),
        Dense(128),
        BatchNormalization(),
        Activation("relu"),
        Dense(128),
        BatchNormalization(),
        Activation("relu"),
        Dense(number_of_categories),
        BatchNormalization(),
        Activation("softmax")
    ])

       
